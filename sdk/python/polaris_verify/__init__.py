# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-verify -- a server-side SDK to verify Polaris identity credentials.

A relying party (a bank, a border kiosk, an online service) drops this into its
backend to answer one narrow question about a credential a holder presented: is it
authentic, and is it authoritative right now? It never returns a person's data.

Two independent checks, deliberately kept apart:

  * AUTHENTICITY -- offline, cryptographic, cacheable. Verify the ML-DSA-65
    signature over SHA3-256(token_value) with a standard library (cryptography /
    OpenSSL, and liboqs as a second witness when present), optionally against a
    set of trusted issuer anchor keys. No network, no Polaris code.
  * AUTHORIZATION -- online, fresh. Ask the issuer's /api/v1/verify, authenticating
    as a registered organization with OAuth2 client-credentials, whether the token
    is authoritative now.

`accept` requires both. Without a reachable issuer the verdict is `provisional`
(authentic, status unverified) -- never a full accept. Self-contained: only the
`cryptography` package plus the standard library.

    from polaris_verify import PolarisVerifier
    v = PolarisVerifier(issuer_url="https://issuer.example",
                        client_id="rp_...", client_secret="...",
                        anchors=["<issuer public key hex>"])
    verdict = v.verify_presentation(presentation)   # -> Verdict(decision="accept", ...)

Conformance: `python -m polaris_verify.conformance` implements the language-agnostic
verifier CLI the published conformance suite drives (see conformance/SPEC.md).
"""
import base64
import dataclasses
import math
import hashlib
import json
import time
import urllib.parse
import urllib.request
from typing import Any, List, Optional

try:
    # The distribution's own version, so the module cannot disagree with what pip installed.
    # It said "0.1.0" through every 1.0.0 release candidate (2026-09-30).
    from importlib.metadata import version as _dist_version
    __version__ = _dist_version("polaris-sdk-python")
except Exception:  # noqa: BLE001  imported from a source tree, not installed
    __version__ = "0+unknown"
ALGORITHM = "ML-DSA-65"   # the default parameter set
# P8.8a: the accepted FIPS 204 parameter sets -> the cryptography witness class. ML-DSA-44 is
# below the floor and is rejected like any unknown algorithm.
ACCEPTED_ALGORITHMS = {"ML-DSA-65": "MLDSA65PublicKey", "ML-DSA-87": "MLDSA87PublicKey",
                       "Falcon-padded-1024": None}
# 2026-10-05: the FN-DSA family (draft FIPS 206), verification only, under the name liboqs gives
# the round-3 scheme it implements (FIPS 206 is not final). cryptography has no Falcon, so the
# value is None and liboqs alone witnesses it here; Falcon-512 (category 1) stays below the floor.


def _accepted(alg):
    """True iff `alg` names an accepted parameter set (total over hostile input)."""
    return isinstance(alg, str) and alg in ACCEPTED_ALGORITHMS


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _unhex(s):
    """`bytes.fromhex`, minus the whitespace it skips between bytes.

    A hex field holds hex digits and nothing else. `bytes.fromhex` also accepts a space between
    two bytes, so a signature written that way verified here and was refused by the TypeScript
    SDK, which in turn read "eg" as 0x0e and accepted what this refused: the same artifact, two
    verdicts. Every hex field is read through this, so all three verifiers read it one way. The
    exceptions are bytes.fromhex's own: TypeError for a value that is not a string, ValueError
    for one that is not hex.
    """
    if isinstance(s, str) and (len(s) % 2 or not _HEX_DIGITS.issuperset(s)):
        raise ValueError("not hex: a hex field holds hex digits and nothing else")
    return bytes.fromhex(s)
PLACEHOLDER_LABEL = "DETERMINISTIC-PLACEHOLDER-SHA3-256"


@dataclasses.dataclass
class AuthenticityVerdict:
    authentic: bool
    issuer_trusted: Optional[bool]   # None when no anchors were supplied
    algorithm: Optional[str]
    note: Optional[str] = None
    witnesses: Optional[List[str]] = None


@dataclasses.dataclass
class Verdict:
    decision: str                    # "accept" | "reject" | "provisional"
    authentic: bool
    issuer_trusted: Optional[bool]
    currently_authoritative: Optional[bool]
    status: Optional[str] = None
    reasons: Optional[List[str]] = None

    def as_dict(self):
        return dataclasses.asdict(self)


def _digest(token_value: str) -> bytes:
    # The signer signs SHA3-256(token_value.encode('utf-8')); reconstruct it.
    return hashlib.sha3_256(token_value.encode("utf-8")).digest()


#: The longest credential serial, in bytes of UTF-8: IdentityToken.token_value is VARCHAR(128).
TOKEN_VALUE_MAX_BYTES = 128


def token_value_serial_problem(token_value):
    """Why `token_value` is not a credential serial, or None when it is one (WIRE-SPEC 3.7).

    A pack is signed over SHA3-256(token_value) with no domain, and every other signed
    artifact over SHA3-256 of its canonical JSON statement, so without this rule any
    authority-signed artifact re-wrapped as a pack (token_value: its canonical statement)
    verified as an authentic credential (2026-09-27, measured with real ML-DSA-65). A serial
    is a non-empty string of at most 128 bytes of UTF-8, not beginning with "{", with no
    control character (U+0000-U+001F, U+007F-U+009F). Every signed statement begins with "{"."""
    if not isinstance(token_value, str):
        return "token_value must be a string, got %s" % type(token_value).__name__
    if not token_value:
        return "token_value is empty"
    try:
        n = len(token_value.encode("utf-8"))
    except UnicodeEncodeError:
        return "token_value is not valid Unicode (an unpaired surrogate)"
    if token_value[0] == "{":
        return "token_value begins with '{', so it is a signed JSON statement, not a credential serial"
    if n > TOKEN_VALUE_MAX_BYTES:
        return "token_value is %d bytes of UTF-8; a credential serial is at most %d" % (n, TOKEN_VALUE_MAX_BYTES)
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in token_value):
        return "token_value contains a control character"
    return None


def _verify_cryptography(digest, sig, pk, alg=ALGORITHM):
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return None
    cls_name = ACCEPTED_ALGORITHMS[alg] if _accepted(alg) else None
    if not cls_name or not hasattr(mldsa, cls_name):
        return None
    try:
        key = getattr(mldsa, cls_name).from_public_bytes(pk)
    except Exception:
        return None
    try:
        key.verify(sig, digest)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _import_oqs():
    """Import liboqs with its startup chatter kept off stdout.

    `import oqs` prints "liboqs-python faulthandler is disabled" to STDOUT. This module IS
    the verifier contract's reference implementation -- conformance/SPEC.md says a verifier
    "prints its verdict as JSON on stdout" and names `python -m polaris_verify.conformance`
    as the example -- so a third party whose runner does json.loads(stdout) got a parse
    error on the first character whenever liboqs was installed.

    Nothing caught it: `run_conformance.py --self` calls this SDK in-process rather than as
    a subprocess, and the CI job that drives a verifier as a subprocess drives the
    TypeScript one, which has no liboqs. Measured by running the documented command.
    """
    import contextlib
    import sys as _sys
    with contextlib.redirect_stdout(_sys.stderr):
        import oqs  # type: ignore
    return oqs


def _verify_liboqs(digest, sig, pk, alg=ALGORITHM):
    if not _accepted(alg):
        return False
    try:
        oqs = _import_oqs()
    except Exception:
        return None
    try:
        with oqs.Signature(alg) as v:
            return bool(v.verify(digest, sig, pk))
    except Exception:
        return False


def verify_authenticity(pack: dict, anchors=None) -> AuthenticityVerdict:
    """Verify a Polaris authenticity pack OFFLINE. `anchors` is an optional
    iterable of trusted issuer public keys (hex); when given, issuer_trusted says
    whether the pack's key is one of them.

    Total on hostile input: a non-dict pack is a verdict, not an exception."""
    # 2026-09-17: this was the ONLY one of eight verify functions without the guard, and it
    # is reachable from the documented top-level API, because `PolarisVerifier
    # .verify_presentation` passes `presentation["credential"]` straight through. A wallet
    # handing over a compact-serialised credential STRING crashed the relying party instead
    # of getting a rejection. The TypeScript SDK returned a verdict for every one of these.
    if not isinstance(pack, dict):
        return AuthenticityVerdict(False, None, None,
                                   note="an authenticity pack must be an object, got %s"
                                        % type(pack).__name__)
    tok = pack.get("token_value")
    alg = pack.get("algorithm")
    if alg != PLACEHOLDER_LABEL and not _accepted(alg):
        return AuthenticityVerdict(False, None, alg, note="unknown or unaccepted signature algorithm: %r" % (alg,))
    sig_hex = pack.get("signature_hex")
    pk_hex = pack.get("public_key_hex")
    if alg == PLACEHOLDER_LABEL or not pk_hex:
        return AuthenticityVerdict(False, None, alg,
                                   note="placeholder credential -- not authenticatable offline")
    if not tok or not sig_hex:
        return AuthenticityVerdict(False, None, alg, note="pack missing token_value or signature_hex")
    try:
        sig, pk = _unhex(sig_hex), _unhex(pk_hex)
    except (ValueError, TypeError):
        return AuthenticityVerdict(False, None, alg, note="signature_hex/public_key_hex are not valid hex")
    # WIRE-SPEC 3.7, 2026-09-27: decided before any signature is checked.
    serial_problem = token_value_serial_problem(tok)
    if serial_problem is not None:
        return AuthenticityVerdict(False, None, alg, note="not an authentic credential: %s" % serial_problem)
    digest = _digest(tok)
    primary = _verify_cryptography(digest, sig, pk, alg)
    witness = _verify_liboqs(digest, sig, pk, alg)
    ran = []
    if primary is not None:
        ran.append("cryptography=%s" % ("valid" if primary else "invalid"))
    if witness is not None:
        ran.append("liboqs=%s" % ("valid" if witness else "invalid"))
    if primary is None and witness is None:
        return AuthenticityVerdict(False, None, alg, witnesses=ran,
                                   note="no ML-DSA-65 verifier available: pip install 'cryptography>=48'")
    if primary is not None and witness is not None and primary != witness:
        return AuthenticityVerdict(False, None, alg, witnesses=ran,
                                   note="the two witnesses DISAGREE -- treat as invalid")
    ok = primary if primary is not None else witness
    trusted = None
    note = None
    if anchors is not None:
        trusted = _hex_in(pk_hex, {_hex_text(a) for a in anchors})
        if ok and not trusted:
            note = "signature is genuine but its key is not in the trusted issuer anchors"
    return AuthenticityVerdict(bool(ok), trusted, alg, note=note, witnesses=ran)


# --- Signed statements (P8.1) -------------------------------------------------
# Every signed artifact except the authenticity pack signs SHA3-256(canonical), where
# canonical is the sorted-keys compact JSON of its signed fields (see
# docs/reference/WIRE-SPEC.md). This is the same construction for all of them, so one
# helper verifies the signature and the per-artifact wrappers add their own rules.
_STATUS_ASSERTION_KEYS = ["format", "token_value", "status", "issued_at", "expires_at"]


def _canonical(obj: dict, keys) -> bytes:
    return json.dumps({k: obj.get(k) for k in keys}, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_over_digest(digest, sig_hex, pk_hex, alg=ALGORITHM):
    """Dual-witness ML-DSA verify over a digest under `alg` (an accepted parameter set).
    Returns (ok, witnesses, note); ok is None when no verifier is available, the witnesses
    disagree, or the algorithm is not accepted."""
    if not _accepted(alg):
        return None, [], "unknown or unaccepted signature algorithm: %r" % (alg,)
    try:
        sig, pk = _unhex(sig_hex), _unhex(pk_hex)
    except (ValueError, TypeError):
        return None, [], "signature_hex/public_key_hex are not valid hex"
    primary = _verify_cryptography(digest, sig, pk, alg)
    witness = _verify_liboqs(digest, sig, pk, alg)
    ran = []
    if primary is not None:
        ran.append("cryptography=%s" % ("valid" if primary else "invalid"))
    if witness is not None:
        ran.append("liboqs=%s" % ("valid" if witness else "invalid"))
    if primary is None and witness is None:
        return None, ran, "no ML-DSA-65 verifier available: pip install 'cryptography>=48'"
    if primary is not None and witness is not None and primary != witness:
        return None, ran, "the two witnesses DISAGREE -- treat as invalid"
    return (primary if primary is not None else witness), ran, None


# ASCII digits only: Python's `\d` also matches Arabic-Indic and every other script's digits,
# and `int()` converts them, so an instant written in them parsed here and nowhere else.
_ISO_INSTANT = __import__("re").compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[Tt ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,6}))?)?)?"
    r"(?:([Zz])|([+-])([0-9]{2}):?([0-9]{2}))?")


def _strict_instant(s):
    """An aware datetime for an ISO 8601 instant in the ONE subset every Polaris verifier
    accepts, or ValueError.

    The same grammar as the TypeScript SDK's isoToEpoch, so the two reference kits and this
    verifier agree on every input. Until 2026-09-24 this was datetime.fromisoformat, whose
    grammar is the interpreter's: Python 3.11 widened it to compact ("20260917T090000Z"),
    week ("2026-W38-4") and hour-only ("T09Z") forms, so the verdict on one artifact depended
    on which Python ran it, and differed from the TypeScript kit, which refuses them. The
    fields are built one by one, so an impossible date ("2026-02-31") is refused rather
    than rolled over."""
    from datetime import datetime, timedelta, timezone
    # The whole string, as written. `strip()` removed a different set of characters than the
    # TypeScript SDK's `trim()` (a file separator here, a byte-order mark there), and `$`
    # matched before a trailing newline; RFC 3339 has no surrounding whitespace (2026-10-01).
    m = _ISO_INSTANT.fullmatch(s) if isinstance(s, str) else None
    if not m:
        raise ValueError("not an ISO 8601 instant in the accepted subset: %r" % (s,))
    y, mo, d, hh, mi, ss, frac, z, sign, oh, om = m.groups()
    micro = int((frac or "").ljust(6, "0") or 0)
    tz = timezone.utc
    if sign and (int(oh) > 23 or int(om) > 59):
        raise ValueError("an offset of %s:%s is not one RFC 3339 allows" % (oh, om))
    if sign:
        shift = timedelta(hours=int(oh), minutes=int(om))
        tz = timezone(shift if sign == "+" else -shift)
    return datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0),
                    micro, tzinfo=tz)


def _iso_to_epoch(s):
    try:
        return _strict_instant(s).timestamp()
    except ValueError:
        return None


#: Formats whose freshness is a REPLAY WINDOW rather than a validity interval, with the
#: age bound in seconds. A holder proof carries `issued_at` and no `expires_at`: it is a
#: presentation made for one verifier at one moment, and the question is not "has it
#: expired" but "is this the one just made for me, or one replayed from earlier".
#:
#: v9.430. Before this the SDK reported `fresh: None` for a holder proof, because
#: _within_window needs both ends and there is only one. The detached verifier has always
#: applied a 300-second bound. Two shipped reference verifiers disagreeing about whether a
#: presentation can be replayed is exactly the divergence the conformance suite exists to
#: catch, and it went unseen because no published case asked about freshness until v9.430.
_REPLAY_WINDOW_SECONDS = {"polaris-holder-proof/1": 300}

#: A proof may be up to this far ahead of the verifier's clock. Matches the detached
#: verifier; a skew allowance the two did not share would be the same bug again, smaller.
_CLOCK_SKEW_SECONDS = 60


#: The longest an access token is cached before the client asks for a new one, whatever the
#: issuer says. 2026-09-17: `int(body.get("expires_in", 300))` took the issuer's word without
#: reading it. `Infinity` survives `json.loads` and raised OverflowError out of a method that
#: only ever promised to return a bearer token; `1e308` was worse, because it converted
#: cleanly and pinned the cached token past the heat death of the process, so a revoked
#: client kept presenting a token it should have stopped using. The issuer is trusted to
#: issue, not trusted to set an unbounded lifetime in the client.
_MAX_TOKEN_CACHE_SECONDS = 24 * 3600
_DEFAULT_TOKEN_CACHE_SECONDS = 300


def _expires_in(value):
    """Seconds to cache an access token: the issuer's number when it is a finite, positive,
    real number within the cache bound, and the conservative default otherwise."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return _DEFAULT_TOKEN_CACHE_SECONDS
    if not math.isfinite(value) or value <= 0:
        return _DEFAULT_TOKEN_CACHE_SECONDS
    return min(int(value), _MAX_TOKEN_CACHE_SECONDS)


def _within_replay_window(obj: dict, now=None):
    """True iff obj was issued no more than its format's window ago, and not implausibly
    far in the future. None if the format has no replay window or the instant is
    unparseable."""
    seconds = _REPLAY_WINDOW_SECONDS.get(obj.get("format"))
    if seconds is None:
        return None
    issued = _iso_to_epoch(obj.get("issued_at"))
    if issued is None:
        return None
    n = _iso_to_epoch(now) if now is not None else time.time()
    if n is None:
        return None
    return (issued <= n + _CLOCK_SKEW_SECONDS) and ((n - issued) <= seconds)


def _within_window(obj: dict, now=None):
    """True iff now is within [issued_at, expires_at). `now` is an ISO-8601 string, or None
    for the current time. None if the window is unparseable."""
    ia, ea = _iso_to_epoch(obj.get("issued_at")), _iso_to_epoch(obj.get("expires_at"))
    if ia is None or ea is None:
        return None
    n = _iso_to_epoch(now) if now is not None else time.time()
    if n is None:
        return None
    return ia <= n < ea


@dataclasses.dataclass
class StatusAssertionVerdict:
    authentic: bool
    fresh: Optional[bool]
    active: Optional[bool]
    status: Optional[str]
    note: Optional[str] = None
    witnesses: Optional[List[str]] = None


def verify_status_assertion(assertion: dict, now=None) -> StatusAssertionVerdict:
    """Verify a Polaris status assertion OFFLINE (P3.6, wire spec section 3.5): the ML-DSA-65
    signature over SHA3-256(canonical statement of {format, token_value, status, issued_at,
    expires_at}); freshness (now within [issued_at, expires_at)); and whether the status is
    ACTIVE. `now` is an ISO-8601 string or None for the current time. No network, no Polaris
    code. A relying party deciding authorization offline requires authentic AND fresh AND
    active, all bound to the presented credential: the same token_value, signed by the credential's
    own public_key_hex (WIRE-SPEC 3.5)."""
    assertion = assertion if isinstance(assertion, dict) else {}
    alg = assertion.get("algorithm")
    status = assertion.get("status")
    if alg == PLACEHOLDER_LABEL or not assertion.get("public_key_hex"):
        return StatusAssertionVerdict(False, None, None, status, "placeholder -- not authenticatable offline")
    if assertion.get("format") != "polaris-status-assertion/1":
        return StatusAssertionVerdict(False, None, None, status, "not a polaris-status-assertion/1")
    digest = hashlib.sha3_256(_canonical(assertion, _STATUS_ASSERTION_KEYS)).digest()
    ok, ran, note = _verify_over_digest(digest, assertion.get("signature_hex"), assertion.get("public_key_hex"),
                                    assertion.get("algorithm"))
    if ok is None:
        return StatusAssertionVerdict(False, None, None, status, note, ran)
    return StatusAssertionVerdict(bool(ok), _within_window(assertion, now), status == "ACTIVE", status,
                                  witnesses=ran)


# The signed-field list per artifact format (wire spec section 3). One generic verifier covers
# every signed statement; the pack (section 3.7) and the status assertion have their own
# entry points because their verdicts differ.
_ARTIFACT_KEYS = {
    "polaris-epoch-checkpoint/1": ["format", "authority", "epoch", "prev", "as_of", "issued_at", "expires_at", "algorithm"],
    "polaris-revocation-feed/1": ["format", "authority", "epoch_number", "as_of", "revoked_root_hex", "revoked_count", "revoked_leaves", "issued_at", "expires_at", "algorithm"],
    "polaris-federation-manifest/1": ["format", "authority", "anchors", "attestations", "epoch", "revocation", "issued_at", "expires_at", "algorithm"],
    "polaris-federation-status-bundle/1": ["format", "publisher", "members_root_hex", "member_count", "issued_at", "expires_at", "algorithm"],
    "polaris-transparency-sth/1": ["format", "log_id", "tree_size", "root_hash_hex", "timestamp"],
    "polaris-timestamp/1": ["format", "authority", "digest_hex", "digest_algorithm", "nonce", "issued_at", "algorithm"],
    "polaris-registry/1": ["format", "publisher", "instance", "authorities", "contexts", "trust", "relying_parties", "issued_at", "expires_at", "algorithm"],
    "polaris-exchange-request/1": ["format", "requester", "target", "context_id", "request_hash", "nonce", "issued_at", "algorithm"],
    "polaris-signed-document/1": ["format", "document", "signer", "on_behalf_of", "purpose", "signed_at", "algorithm"],
    "polaris-id-token/1": ["format", "iss", "sub", "aud", "nonce", "context_id", "disclosure_level", "acr", "enrollment", "auth_time", "iat", "exp", "algorithm"],
    "polaris-trust-list/1": ["format", "publisher", "keys", "issued_at", "expires_at", "algorithm"],
    "polaris-exchange-receipt/1": ["format", "requester", "responder", "context_id", "request_hash", "response_hash", "authorized_via", "occurred_at", "algorithm"],
    "polaris-exchange-mint/1": ["format", "requester_public_key_hex", "context_id", "request_hash", "response_hash", "responder_agency_id", "occurred_at"],
    # P9.5: the attesting agency's own signature over a federation trust edge.
    "polaris-trust-attestation/1": ["format", "attesting_agency_id", "attested_agency_id", "attested_public_key_hex", "context_id", "attested_date", "valid_until", "algorithm"],
    # P9.1: the issuer's binding of a holder key, and the holder's own proof of it.
    "polaris-holder-binding/1": ["format", "token_value", "holder_public_key_hex", "holder_algorithm", "bound_at", "status", "issued_at", "expires_at", "algorithm"],
    "polaris-holder-proof/1": ["format", "token_value", "context_id", "verifier_nonce", "issued_at", "algorithm"],
    # P9.8: delegation. Signed by the HOLDER's key and the AGENT's, never the issuer's.
    "polaris-agent-grant/1": ["format", "grant_id", "agent_public_key_hex", "agent_algorithm",
                              "actions", "limits", "context_id", "issued_at", "expires_at", "algorithm"],
    "polaris-grant-revocation/1": ["format", "grant_id", "revoked_at", "algorithm"],
    "polaris-agent-proof/1": ["format", "grant_id", "action", "service_nonce", "issued_at", "algorithm"],
    # P9.2: the published anonymity set a holder proves against on their own device.
    "polaris-epoch-leaves/1": ["format", "authority", "epoch_id", "context_id", "merkle_root", "leaf_count", "leaves_root_hex", "issued_at", "expires_at", "algorithm"],
}


@dataclasses.dataclass
class ArtifactVerdict:
    authentic: bool
    fresh: Optional[bool]
    note: Optional[str] = None
    witnesses: Optional[List[str]] = None
    #: Whether the key that signed this artifact is one the caller trusts. None when no
    #: anchors were supplied, which is the honest answer to a question nobody asked.
    #:
    #: v9.430. The SDK could not answer this for any windowed artifact: a caller learned
    #: that a trust list, registry, manifest, timestamp, ID token, holder binding or epoch
    #: bundle carried a valid signature, and had no way to learn whose. The detached
    #: verifier has always taken anchors for all seven. Authenticity without trust is the
    #: distinction v9.420 drew for the ID token's audience, one level out: a genuine
    #: signature by a stranger is genuine and worthless.
    issuer_trusted: Optional[bool] = None


def _leaves_are_hex(leaves):
    """WIRE-SPEC 3.3 and 3.16: a revoked leaf and an epoch leaf are each a SHA3-256, so a list of
    64 hex digits in either case. Until 2026-10-01 a leaf of any type was turned into a string
    before hashing, and Python and JavaScript turn `null` and `1.0` into different strings, so
    one signed feed had two verdicts; a field that was not a list read as the empty set."""
    return isinstance(leaves, list) and all(
        isinstance(x, str) and len(x) == 64 and all(c in "0123456789abcdefABCDEF" for c in x)
        for x in leaves)


def _revoked_root(leaves) -> str:
    if not isinstance(leaves, (list, tuple)):
        leaves = []
    uniq = sorted({str(x).lower() for x in leaves})
    return hashlib.sha3_256("\n".join(uniq).encode("utf-8")).hexdigest()


def _count_is(count, n) -> bool:
    """A signed count equals `n`, read as JSON: a number, never a boolean. Python's `True == 1`
    otherwise accepts `"member_count": true` for one member, which the TypeScript SDK's `===`
    refuses; the same artifact would get two verdicts."""
    return isinstance(count, (int, float)) and not isinstance(count, bool) and count == n


def _wire_int(x) -> int:
    """An inclusion proof's index or tree size, read as a JSON integer: a finite number with
    no fractional part, never a boolean or a string. Raises ValueError otherwise. `int()`
    alone read 1.5 as 1 and "1" and true as 1, and the TypeScript SDK's `Number()` read null
    and false as 0, so the same proof was anchored under one SDK and refused under the other
    (2026-09-30)."""
    if (isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x)
            or (isinstance(x, float) and not x.is_integer())):
        raise ValueError("not a JSON integer: %r" % (x,))
    return int(x)


def _wire_path(p) -> list:
    """An inclusion proof's audit path: absent or null is empty, a list is read element by
    element, and anything else is malformed rather than read as empty or iterated."""
    if p is None:
        return []
    if not isinstance(p, list):
        raise ValueError("an inclusion proof's path must be a list")
    return [_unhex(str(x)) for x in p]


def _members_root(members) -> str:
    if not isinstance(members, list):
        members = []
    digs = sorted(hashlib.sha3_256(json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
                  for m in members)
    return hashlib.sha3_256("\n".join(digs).encode("utf-8")).hexdigest()


@dataclasses.dataclass
class IdTokenVerdict:
    authentic: bool
    audience_matches: Optional[bool]
    nonce_matches: Optional[bool]
    fresh: Optional[bool]
    sub: Optional[str]
    acr: Optional[str]
    note: Optional[str] = None
    #: v9.431: whether the agency that signed the token is one this relying party trusts.
    #: None when no anchors were supplied. A genuine token from an agency you have never
    #: heard of is genuine and meaningless, which is the same distinction v9.420 drew
    #: about the audience one level in.
    issuer_trusted: Optional[bool] = None


def verify_id_token(tok: dict, audience=None, nonce=None, now=None,
                    anchors=None) -> IdTokenVerdict:
    """Verify a polaris-id-token/1 (P8.4) as a relying party, offline: the issuing agency's
    signature, that it was issued to THIS audience, that it carries the login's nonce, and
    freshness (iat <= now < exp). The subject is a credential hash, never a person."""
    tok = tok if isinstance(tok, dict) else {}
    if tok.get("format") != "polaris-id-token/1":
        return IdTokenVerdict(False, None, None, None, tok.get("sub"), tok.get("acr"), "not a polaris-id-token/1")
    base = verify_signed_artifact(tok, now, anchors=anchors)
    if not base.authentic:
        return IdTokenVerdict(False, None, None, None, tok.get("sub"), tok.get("acr"),
                              base.note, base.issuer_trusted)
    ia, ea = _iso_to_epoch(tok.get("iat")), _iso_to_epoch(tok.get("exp"))
    n = _iso_to_epoch(now) if now is not None else time.time()
    fresh = (ia <= n < ea) if (ia is not None and ea is not None and n is not None) else None
    return IdTokenVerdict(True, (tok.get("aud") == audience) if audience is not None else None,
                          (tok.get("nonce") == nonce) if nonce is not None else None, fresh,
                          tok.get("sub"), tok.get("acr"), None, base.issuer_trusted)


def _status_of(entry):
    """The status an anchor, key or binding states: "active" when it states none (absent or
    null), otherwise exactly what it states. A status of false or "" is a value that names no
    state, so it is not "active". Until 2026-10-01 this read `entry.get("status") or
    "active"`, which made those two active here while the TypeScript SDK refused them: three
    verifiers, two answers, on the same signed bytes."""
    status = entry.get("status")
    return "active" if status is None else status


def verify_signed_artifact(obj: dict, now=None, anchors=None) -> ArtifactVerdict:
    """Verify a Polaris signed artifact's AUTHENTICITY offline (P8.1, wire spec section 3): for
    the epoch checkpoint, revocation feed, federation manifest, status bundle, or transparency
    STH, recompute the canonical statement for its `format`, verify the ML-DSA-65 signature over
    its SHA3-256, check freshness for a windowed artifact, and check the artifact's commitment
    (feed/bundle) or self-consistency (manifest). Standalone. Reports authentic + fresh. The
    federation TRUST decision (accepting a foreign credential across authorities) is a separate,
    composite check, not this per-artifact authenticity."""
    obj = obj if isinstance(obj, dict) else {}
    fmt = obj.get("format")
    # A string first: `format` is the sender's, and a list or an object is unhashable, which
    # raised TypeError out of every artifact check (2026-09-28).
    keys = _ARTIFACT_KEYS.get(fmt) if isinstance(fmt, str) else None
    if keys is None:
        return ArtifactVerdict(False, None, "unknown or unsupported artifact: %s" % fmt)
    if obj.get("algorithm") == PLACEHOLDER_LABEL or not obj.get("public_key_hex"):
        return ArtifactVerdict(False, None, "placeholder -- not authenticatable offline")
    ok, ran, note = _verify_over_digest(hashlib.sha3_256(_canonical(obj, keys)).digest(),
                                        obj.get("signature_hex"), obj.get("public_key_hex"), obj.get("algorithm"))
    if ok is None:
        return ArtifactVerdict(False, None, note, ran)
    ok = bool(ok)
    if ok and fmt == "polaris-revocation-feed/1":
        # WIRE-SPEC 3.3: `revoked_count` MUST equal the number of distinct leaves; only the root
        # was compared until 2026-09-30, where the detached verifier compared both.
        leaves = obj.get("revoked_leaves") if isinstance(obj.get("revoked_leaves"), list) else []
        ok = (_leaves_are_hex(obj.get("revoked_leaves"))
              and _revoked_root(leaves) == _hex_text(obj.get("revoked_root_hex"))
              and _count_is(obj.get("revoked_count"), len({str(x).lower() for x in leaves})))
        note = None if ok else "the revocation feed's commitment or count does not match its leaves"
    elif ok and fmt == "polaris-agent-grant/1":
        # WIRE-SPEC 3.17: `grant_id` is the revocation handle and names this grant alone. A grant
        # without one as text could never be revoked once a revocation names a grant as text
        # (2026-10-01), so it is not a grant.
        ok = _wire_text(obj.get("grant_id")) is not None
        note = None if ok else "a grant names itself: its grant_id is its revocation handle"
    elif ok and fmt == "polaris-signed-document/1":
        # WIRE-SPEC 3.12: the document's `digest_algorithm` MUST be SHA3-256 and `digest_hex` its
        # lowercase hex, as for a timestamp. No verifier here checked either until 2026-10-01.
        d = obj.get("document") if isinstance(obj.get("document"), dict) else {}
        dh = d.get("digest_hex")
        ok = (d.get("digest_algorithm") == "SHA3-256" and isinstance(dh, str) and len(dh) == 64
              and all(c in "0123456789abcdef" for c in dh))
        note = None if ok else "a signed document binds a lowercase SHA3-256 digest"
    elif ok and fmt == "polaris-timestamp/1":
        # WIRE-SPEC 3.9: `digest_algorithm` MUST be SHA3-256 and `digest_hex` its lowercase hex; and
        # the instant must be one. Until 2026-09-30 none of the three was checked here.
        dh = obj.get("digest_hex")
        ok = (obj.get("digest_algorithm") == "SHA3-256" and isinstance(dh, str) and len(dh) == 64
              and all(c in "0123456789abcdef" for c in dh))
        if ok:
            try:
                _strict_instant(obj.get("issued_at"))
            except (TypeError, ValueError):
                ok = False
        note = None if ok else "a timestamp binds a lowercase SHA3-256 digest at a valid instant"
    elif ok and fmt == "polaris-epoch-leaves/1":
        # P9.2: the leaves ride outside the signed statement, committed to by leaves_root_hex,
        # so a verifier checks the set with SHA3-256 alone and never needs the proving library.
        leaves = obj.get("all_leaves_hex") if isinstance(obj.get("all_leaves_hex"), list) else []
        ok = (_leaves_are_hex(obj.get("all_leaves_hex"))
              and _revoked_root(leaves) == _hex_text(obj.get("leaves_root_hex"))
              and _count_is(obj.get("leaf_count"), len(leaves)))
        note = None if ok else "the published leaves do not match the committed set"
    elif ok and fmt == "polaris-federation-status-bundle/1":
        # 2026-09-30: WIRE-SPEC 3.4 says member_count MUST equal the number of members, and
        # only the detached verifier checked it: a bundle whose signed count and listed
        # members disagreed was authentic here and in the TypeScript SDK.
        members = obj.get("members") if isinstance(obj.get("members"), list) else []
        ok = (_members_root(members) == _hex_text(obj.get("members_root_hex"))
              and _count_is(obj.get("member_count"), len(members)))
        note = None if ok else "the status bundle's members_root or member_count does not match its members"
    elif ok and fmt == "polaris-federation-manifest/1":
        active = {_hex_text(a.get("public_key_hex", "")) for a in (obj.get("anchors") or [])
                  if isinstance(a, dict) and _status_of(a) == "active"}
        ok = _hex_in(obj.get("public_key_hex"), active)
        note = None if ok else "the manifest is not signed by one of its own active anchors"
    elif ok and fmt == "polaris-registry/1":
        pub = obj.get("publisher") if isinstance(obj.get("publisher"), dict) else {}
        listed = [_hex_text(a.get("public_key_hex")) for a in (obj.get("authorities") or [])
                  if isinstance(a, dict) and _same_id(a.get("agency_id"), pub.get("agency_id"))
                  and _status_of(a) == "active"]
        ok = _hex_in(obj.get("public_key_hex"), listed)
        note = None if ok else "the registry is not signed by the key it lists for its own publisher"
    elif ok and fmt == "polaris-trust-list/1":
        pub = obj.get("publisher") if isinstance(obj.get("publisher"), dict) else {}
        active = [_hex_text(k.get("public_key_hex")) for k in (obj.get("keys") or [])
                  if isinstance(k, dict) and _same_id(k.get("agency_id"), pub.get("agency_id")) and k.get("status") == "active"]
        ok = _hex_in(obj.get("public_key_hex"), active)
        note = None if ok else "the trust list is not signed by a key it lists as active for its own publisher"
    # A replay-windowed format answers freshness the other way round; _within_window
    # needs both ends of an interval and such an artifact has only its issuance.
    fresh = _within_replay_window(obj, now)
    if fresh is None:
        fresh = _within_window(obj, now)
    # Same rule as the detached verifier: the key that signed it, lowercased, is in the
    # anchor set. None when the caller supplied none.
    trusted = None
    if anchors is not None:
        try:
            trusted = _hex_in(obj.get("public_key_hex", ""), {_hex_text(a) for a in anchors})
        except TypeError:
            trusted = False
    return ArtifactVerdict(ok, fresh, note, ran, trusted)


# --- P9.6: timestamp anchor verification (was P8.5c) --------------------------------
# Long-term validation asks whether a signature was valid at the instant it was made.
# A timestamp alone does not settle it: whoever holds the timestamp authority's key can
# mint a backdated one. An ANCHORED timestamp is different. Its digest is an entry in an
# append-only log whose head is published and cosigned by witnesses, so a forgery has to
# be absent from every witnessed head of its claimed era. Until now only the detached
# verifier could check that, which put the strongest form of long-term validation behind
# Polaris's own tooling. These four functions put it in the SDK an outsider installs.
_TIMESTAMP_LOG_ID = "polaris-timestamp-log"
_STH_FORMAT = "polaris-transparency-sth/1"
_COSIGNATURE_FORMAT = "polaris-transparency-cosignature/1"
_COSIGNATURE_KEYS = ["format", "log_id", "tree_size", "root_hash_hex"]


def timestamp_hash(ts: dict) -> str:
    """A timestamp's entry in the timestamp transparency log: the SHA3-256 hex of the same
    canonical statement its signature covers."""
    keys = _ARTIFACT_KEYS["polaris-timestamp/1"]
    return hashlib.sha3_256(_canonical(ts if isinstance(ts, dict) else {}, keys)).hexdigest()


def _leaf_hash(entry_hex: str) -> bytes:
    """RFC 6962 leaf hash, SHA3-256(0x00 || entry), the entry taken as its UTF-8 bytes."""
    return hashlib.sha3_256(b"\x00" + str(entry_hex).encode("utf-8")).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash, SHA3-256(0x01 || left || right)."""
    return hashlib.sha3_256(b"\x01" + left + right).digest()


def verify_inclusion(idx: int, tree_size: int, leaf: bytes, root: bytes, proof) -> bool:
    """RFC 6962 section 2.1.1: is `leaf` the entry at `idx` in a tree of `tree_size` whose
    head is `root`? Total on hostile input: a malformed path is False, never an exception."""
    try:
        idx, tree_size = _wire_int(idx), _wire_int(tree_size)
    except (TypeError, ValueError, OverflowError):
        return False
    if idx < 0 or idx >= tree_size:
        return False
    fn, sn, r = idx, tree_size - 1, leaf
    for pnode in proof:
        if sn == 0 or not isinstance(pnode, (bytes, bytearray)):
            return False
        if (fn & 1) or (fn == sn):
            r = _node_hash(bytes(pnode), r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, bytes(pnode))
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_cosignature(cosig: dict, witness_key=None) -> ArtifactVerdict:
    """Verify a witness cosignature over a log head: the ML-DSA signature over the SHA3-256
    of the canonical (format, log_id, tree_size, root_hash_hex), and with `witness_key` that
    it came from the expected witness. `fresh` is None: a cosignature carries no window."""
    c = cosig if isinstance(cosig, dict) else {}
    if c.get("format") != _COSIGNATURE_FORMAT:
        return ArtifactVerdict(False, None, "not a %s" % _COSIGNATURE_FORMAT)
    if c.get("algorithm") == PLACEHOLDER_LABEL or not c.get("public_key_hex"):
        return ArtifactVerdict(False, None, "placeholder cosignature -- not authenticatable offline")
    ok, ran, note = _verify_over_digest(hashlib.sha3_256(_canonical(c, _COSIGNATURE_KEYS)).digest(),
                                        c.get("signature_hex"), c.get("public_key_hex"), c.get("algorithm"))
    if ok is None:
        return ArtifactVerdict(False, None, note, ran)
    if ok and witness_key is not None and not _same_hex(c.get("public_key_hex"), witness_key):
        return ArtifactVerdict(False, None, "the cosignature is not from the expected witness", ran)
    return ArtifactVerdict(bool(ok), None, None if ok else "cosignature signature is invalid", ran)


@dataclasses.dataclass
class AnchorVerdict:
    anchored: bool
    sth_authentic: bool
    witnessed: Optional[bool]
    cosigner_count: int
    timestamp_hash: Optional[str]
    index: Optional[int]
    tree_size: Optional[int]
    note: Optional[str] = None


def verify_timestamp_anchor(ts: dict, log_key=None, trusted_witnesses=None, threshold: int = 1) -> AnchorVerdict:
    """Verify OFFLINE that a timestamp is ANCHORED in the timestamp transparency log: its
    unsigned `anchor` carries an inclusion proof and a Signed Tree Head, the proof is for this
    timestamp's own hash, the head is an authentic head of that log (with `log_key`, signed by
    the expected authority), and the proof reconstructs the head. With `trusted_witnesses`, the
    head must also be cosigned by `threshold` DISTINCT trusted witnesses: a stolen authority key
    can sign a fresh head over a fabricated log, but it cannot make a witness have cosigned that
    head at the claimed time. No network, no Polaris code. Total on hostile input."""
    v = AnchorVerdict(False, False, None, 0, None, None, None, None)
    if not isinstance(ts, dict):
        v.note = "timestamp must be an object"
        return v
    anchor = ts.get("anchor")
    if not isinstance(anchor, dict):
        v.note = "the timestamp carries no anchor (unanchored: the authority kept no record of it)"
        return v
    proof, sth = anchor.get("proof"), anchor.get("sth")
    if not isinstance(proof, dict) or not isinstance(sth, dict):
        v.note = "anchor.proof and anchor.sth must be objects"
        return v
    v.timestamp_hash = timestamp_hash(ts)
    if _hex_text(proof.get("entry_hex")) != v.timestamp_hash:
        v.note = "the proof is not for this timestamp"
        return v
    # A head is a signed tree head: its log_id, tree_size and root are what its signature covers.
    # Any other artifact the log key signed carries those fields UNSIGNED, so "signed by the log
    # key" is not "a head of the log". Until 2026-09-30 a timestamp signed by that key, with a
    # tree invented beside it, anchored itself; the detached verifier refused it.
    if sth.get("format") != _STH_FORMAT:
        v.note = "the head is not a %s" % _STH_FORMAT
        return v
    sv = verify_signed_artifact(sth)
    v.sth_authentic = bool(sv.authentic)
    if sth.get("log_id") != _TIMESTAMP_LOG_ID or proof.get("log_id") not in (None, _TIMESTAMP_LOG_ID):
        v.note = "the head is not a %s head" % _TIMESTAMP_LOG_ID
        return v
    try:
        idx, size = _wire_int(proof.get("index")), _wire_int(proof.get("tree_size"))
        root = _unhex(str(sth.get("root_hash_hex")))
        path = _wire_path(proof.get("proof_hex"))
    except (TypeError, ValueError, OverflowError):
        v.note = "malformed proof"
        return v
    v.index, v.tree_size = idx, size
    if size != sth.get("tree_size") or \
            not _same_hex(proof.get("root_hash_hex"), sth.get("root_hash_hex")):
        v.note = "the proof and the head describe different trees"
        return v
    if not v.sth_authentic:
        v.note = sv.note or "the head is not authentic"
        return v
    if log_key is not None and not _same_hex(sth.get("public_key_hex"), log_key):
        v.note = "the head is not signed by the expected log key"
        return v
    v.anchored = verify_inclusion(idx, size, _leaf_hash(v.timestamp_hash), root, path)
    if not v.anchored:
        v.note = "the inclusion proof does not reconstruct the head"
        return v
    if trusted_witnesses is not None:
        trusted = {_hex_text(t) for t in trusted_witnesses}
        seen = set()
        cosignatures = anchor.get("cosignatures")
        # A list, or nothing witnessed: `True` raised TypeError out of a check that says it
        # is total on hostile input (2026-09-28).
        for c in (cosignatures if isinstance(cosignatures, list) else []):
            if not isinstance(c, dict) or not verify_cosignature(c).authentic:
                continue
            if (c.get("log_id") == sth.get("log_id") and c.get("tree_size") == sth.get("tree_size")
                    and _same_hex(c.get("root_hash_hex"), sth.get("root_hash_hex"))):
                w = _hex_text(c.get("public_key_hex"))
                if w is not None and w in trusted:
                    seen.add(w)
        v.cosigner_count = len(seen)
        # A threshold is a whole number of witnesses, at least one: 0.5 and -1 were met by no
        # cosignature at all, and the two SDKs disagreed at 0.5 (2026-09-30).
        if (isinstance(threshold, bool) or not isinstance(threshold, (int, float))
                or not float(threshold).is_integer() or threshold < 1):
            v.witnessed = False
            v.note = "the witness threshold must be a whole number of at least 1, got %r" % (threshold,)
        else:
            v.witnessed = v.cosigner_count >= int(threshold)
            if not v.witnessed:
                v.note = "only %d trusted witness cosignature(s) over this head, need %d" % (v.cosigner_count, threshold)
    return v


@dataclasses.dataclass
class CrossAuthorityVerdict:
    decision: str                    # "accept" | "reject"
    authentic: bool
    issuer_trusted: Optional[bool]   # None when no trust anchors were given
    via: Any = None
    reason: Optional[str] = None
    # P9.5: was the trust edge signed by the agency that made it, or is it an unsigned
    # legacy row the manifest's signature carries on an operator's behalf? None when no
    # edge was found. A relying party that requires signatures passes
    # require_signed_attestation; one that merely wants to know reads this.
    attestation_signed: Optional[bool] = None


@dataclasses.dataclass
class HolderVerdict:
    proved: bool
    binding_authentic: Optional[bool]
    bound_to_credential: Optional[bool]
    binding_fresh: Optional[bool]
    proof_authentic: Optional[bool]
    key_matches_binding: Optional[bool]
    nonce_matches: Optional[bool]
    note: Optional[str] = None
    credential_authentic: Optional[bool] = None
    issuer_trusted: Optional[bool] = None     # None when no anchors were given


def verify_holder(credential: dict, binding: dict, proof: dict, expected_nonce=None,
                  expected_context=None, now=None, max_age_seconds: int = 300,
                  anchors=None) -> HolderVerdict:
    """Decide the holder key chain offline (P9.1): issuer anchor -> binding -> holder key -> proof.

    Polaris was issuer-centric until v9.349: a holder held a credential, not a key pair, so
    presenting the file was the whole of the proof. A holder proof answers a different
    question, whether the party presenting it holds the key the ISSUER bound to that
    credential. The proof is signed over the credential, the context, the verifier's nonce
    and the instant, and deliberately NOT over the presented code, so a coerced presentation
    stays byte-indistinguishable from a consenting one.

    `proved` needs the credential's own signature to verify and the verifier's own
    `expected_nonce` to match: a proof checked against no nonce is replayable, and a chain whose
    credential does not verify binds a key to nothing. With `anchors`, the credential's issuer
    must also be one of them (`issuer_trusted`); without, `issuer_trusted` is None."""
    v = HolderVerdict(False, None, None, None, None, None, None)
    b = binding if isinstance(binding, dict) else {}
    pr = proof if isinstance(proof, dict) else {}
    if b.get("format") != "polaris-holder-binding/1" or pr.get("format") != "polaris-holder-proof/1":
        v.note = "a holder chain needs a polaris-holder-binding/1 and a polaris-holder-proof/1"
        return v
    bv = verify_signed_artifact(b, now=now)
    v.binding_authentic, v.binding_fresh = bv.authentic, bv.fresh
    cred = credential if isinstance(credential, dict) else {}
    # 2026-09-30: the credential was compared with the binding and never verified, and no nonce
    # was required, so a chain an attacker signed end to end under a key of their own, replayed
    # without the verifier's challenge, was proved.
    av = verify_authenticity(cred, anchors)
    v.credential_authentic, v.issuer_trusted = av.authentic, av.issuer_trusted
    v.bound_to_credential = (_wire_text_equal(b.get("token_value"), cred.get("token_value"))
                             and _same_hex(b.get("public_key_hex"), cred.get("public_key_hex")))
    keys = _ARTIFACT_KEYS["polaris-holder-proof/1"]
    ok, ran, note = _verify_over_digest(hashlib.sha3_256(_canonical(pr, keys)).digest(),
                                        pr.get("signature_hex"), pr.get("public_key_hex"), pr.get("algorithm"))
    v.proof_authentic = None if ok is None else bool(ok)
    if ok is None:
        # A proof that cannot be checked (an algorithm outside the accepted set, or no verifier)
        # says nothing about its key, credential or nonce, as in the TypeScript SDK, which stops
        # here; this went on and reported nonce_matches True for it (2026-10-01).
        v.note = note
        return v
    # The proof names the credential it is about (`token_value`, which the holder signed); it
    # must be this one. Until 2026-09-30 only the key was compared, so a proof made for one
    # credential passed with another bound to the same holder key.
    v.key_matches_binding = (_same_hex(pr.get("public_key_hex"), b.get("holder_public_key_hex"))
                             and _wire_text_equal(pr.get("token_value"), b.get("token_value"))
                             and _status_of(b) == "active")
    # A nonce and a context read as the TypeScript SDK reads them: str() spelled true "True" and
    # 1e-05 "1e-05" where String() spells them "true" and "0.00001", and == read True as context 1
    # (2026-10-01).
    if expected_nonce is not None:
        v.nonce_matches = _wire_text_equal(pr.get("verifier_nonce"), expected_nonce)
    ctx_ok = expected_context is None or _same_id(pr.get("context_id"), expected_context)
    issued = _iso_to_epoch(pr.get("issued_at"))
    ref = _iso_to_epoch(now) if now else __import__("time").time()
    fresh = issued is not None and ref is not None and issued <= ref + 60 and (ref - issued) <= max_age_seconds
    v.proved = bool(v.credential_authentic and v.issuer_trusted is not False
                    and v.binding_authentic and v.binding_fresh and v.bound_to_credential
                    and v.proof_authentic and v.key_matches_binding
                    and v.nonce_matches is True and ctx_ok and fresh)
    if not v.proved:
        if expected_nonce is None:
            v.note = "no nonce was expected: a holder proof checked against no challenge is replayable"
        elif not v.credential_authentic:
            v.note = "the credential's own signature does not verify"
        elif v.issuer_trusted is False:
            v.note = "the credential's issuer key is not in the anchors"
        else:
            v.note = "the holder proof does not chain to a fresh issuer-signed binding for this credential"
    return v


def verify_attestation(att: dict, attesting_agency_id=None, expected_key=None) -> ArtifactVerdict:
    """Verify that a federation attestation carries the ATTESTING agency's own signature over
    the attested key, the context and the window (P9.5).

    Before v9.348 an attestation was a row an operator recorded, and the manifest that
    published it signed whatever the table held, so a row inserted straight into a database
    was indistinguishable from one made through the ceremony. An unsigned attestation is not
    a failure but legacy: `authentic` is False with a note, and the caller decides whether to
    require a signature. `fresh` is None; an attestation's window is its `valid_until`, which
    the trust decision reads."""
    a = att if isinstance(att, dict) else {}
    if not a.get("signature_hex") and not a.get("public_key_hex"):
        return ArtifactVerdict(False, None, "unsigned legacy attestation (recorded before v9.348)")
    if a.get("format") != "polaris-trust-attestation/1":
        return ArtifactVerdict(False, None, "not a polaris-trust-attestation/1")
    if a.get("algorithm") == PLACEHOLDER_LABEL:
        return ArtifactVerdict(False, None, "placeholder attestation signature -- not authenticatable offline")
    keys = _ARTIFACT_KEYS["polaris-trust-attestation/1"]
    ok, ran, note = _verify_over_digest(hashlib.sha3_256(_canonical(a, keys)).digest(),
                                        a.get("signature_hex"), a.get("public_key_hex"), a.get("algorithm"))
    if ok is None:
        return ArtifactVerdict(False, None, note, ran)
    if ok and attesting_agency_id is not None and not _same_id(a.get("attesting_agency_id"), attesting_agency_id):
        return ArtifactVerdict(False, None, "the attestation names a different attesting agency "
                                            "than the manifest that published it", ran)
    if ok and expected_key is not None and \
            not _same_hex(a.get("attested_public_key_hex"), expected_key):
        return ArtifactVerdict(False, None, "the attestation is signed over a different attested key", ran)
    return ArtifactVerdict(bool(ok), None, None if ok else "the attestation signature is invalid", ran)


def verify_cross_authority(pack: dict, context_id, manifests, trusted_anchors=None,
                           revocation_feed=None, now=None,
                           require_signed_attestation: bool = False) -> CrossAuthorityVerdict:
    """Decide a FOREIGN credential across authorities OFFLINE (P8.1, wire spec section 4).
    Accept iff: the authenticity pack is genuine; some federation manifest the relying party
    trusts (authentic, fresh, and signed by one of `trusted_anchors`) attests the credential's
    signing key in the presented context, non-transitively; and, if a revocation feed is
    supplied, the credential is not revoked (the feed authentic, fresh, and bound to the
    issuer's key). With no `trusted_anchors` nothing is trusted: the decision is reject and
    `issuer_trusted` is None. Standalone, no network."""
    pack = pack if isinstance(pack, dict) else {}
    a = verify_authenticity(pack)
    if not a.authentic:
        return CrossAuthorityVerdict("reject", False, False, reason="credential is not authentic")
    token_key = _hex_text(pack.get("public_key_hex"))
    if trusted_anchors is None:
        # No root, no trusted authority. Every manifest is signed by a key it lists itself, so
        # with no anchor the relying party chose, an attacker's own manifest attesting the
        # attacker's own credential decided (2026-09-30). The detached verifier's equivalent takes
        # `trusted_manifests`, a set its caller vouches for by name; this function takes the
        # manifests a presentation brought, so it trusts none of them unaided.
        return CrossAuthorityVerdict("reject", True, None,
                                     reason="no trust anchors were given: a manifest vouches for nothing by itself")
    trusted = {_hex_text(t) for t in trusted_anchors}
    via = None
    signed_edge = None
    # A manifest set that is not a list is no manifests, as in the detached verifier: `or []`
    # let `true` through to the loop, which raised TypeError (2026-09-30).
    for m in (manifests if isinstance(manifests, (list, tuple)) else []):
        m = m if isinstance(m, dict) else {}
        mv = verify_signed_artifact(m, now=now)   # manifest: signature + self-consistency + freshness
        if not (mv.authentic and mv.fresh):
            continue
        # Trusted iff the key that SIGNED the manifest (one of its own active anchors, which
        # verify_signed_artifact requires) is one the relying party trusts. Until 2026-09-30 it
        # was any key the manifest merely LISTED, so an attacker's manifest that listed the
        # relying party's anchor beside the attacker's own root was trusted (WIRE-SPEC section 4).
        if not _hex_in(m.get("public_key_hex"), trusted):
            continue   # the relying party does not trust this manifest's signer
        for att in (m.get("attestations") or []):
            if not isinstance(att, dict):
                continue
            if (token_key is not None and _hex_text(att.get("attested_public_key_hex")) == token_key
                    and _same_id(att.get("context_id"), context_id)):
                # In-context means a context was presented (WIRE-SPEC section 4); before
                # 2026-09-27 a missing one matched an edge from ANY context.
                # P9.5: is the edge signed by the agency that made it, or is it the
                # operator's word carried by the manifest's signature?
                auth = m.get("authority") if isinstance(m.get("authority"), dict) else {}
                av = verify_attestation(att, attesting_agency_id=auth.get("agency_id"), expected_key=token_key)
                unsigned = not att.get("signature_hex") and not att.get("public_key_hex")
                # A signed edge is the attesting agency's only if one of ITS roots signed it: the
                # key must be among the carrying manifest's active anchors (2026-09-30; until then
                # any key's valid signature counted, so a stranger met require_signed_attestation).
                roots = {_hex_text(x.get("public_key_hex")) for x in (m.get("anchors") or [])
                         if isinstance(x, dict) and _status_of(x) == "active"}
                if not unsigned and (not av.authentic
                                     or not _hex_in(att.get("public_key_hex"), roots)):
                    continue    # a present-but-bad signature is worse than none: refuse the edge
                # An edge whose own window has closed is not an edge, however fresh the manifest
                # carrying it (WIRE-SPEC section 4). Until 2026-09-27 this decision never read
                # `valid_until`, and until 2026-09-28 it read it only for a SIGNED edge. A legacy
                # edge that states no window stays open.
                if not _attestation_open(att, now):
                    continue
                if require_signed_attestation and unsigned:
                    continue
                signed_edge = not unsigned
                via = m.get("authority")
                break
        if via is not None:
            break
    if via is None:
        return CrossAuthorityVerdict("reject", True, False,
                                     reason="no trusted authority attests to this credential's issuer in this context")
    # The authority the edge was found under, as the manifest names it (an object), as the
    # TypeScript SDK reports it; until 2026-09-30 anything but a string became None, so it
    # always did.
    via_str = via
    if revocation_feed is not None:
        # A feed that is not an object is not authentic, as in the detached verifier; the
        # binding below read `.get` off it and raised AttributeError (2026-09-28).
        feed = revocation_feed if isinstance(revocation_feed, dict) else {}
        rv = verify_signed_artifact(feed, now=now)
        bound = token_key is not None and _hex_text(feed.get("public_key_hex")) == token_key
        if not (rv.authentic and rv.fresh and bound):
            return CrossAuthorityVerdict("reject", True, True, via_str,
                                         "the issuer's revocation feed is not authentic, fresh, and bound to the issuer key",
                                         signed_edge)
        leaf = hashlib.sha3_256(str(pack.get("token_value") or "").encode("utf-8")).hexdigest()
        if leaf in {str(x).lower() for x in (feed.get("revoked_leaves") or [])}:
            return CrossAuthorityVerdict("reject", True, True, via_str,
                                         "credential is revoked in the issuer's published feed", signed_edge)
    return CrossAuthorityVerdict("accept", True, True, via_str, None, signed_edge)


class PolarisVerifier:
    def __init__(self, issuer_url=None, client_id=None, client_secret=None,
                 anchors=None, timeout=30):
        self.issuer_url = issuer_url.rstrip("/") if issuer_url else None
        self.client_id = client_id
        self.client_secret = client_secret
        self.anchors = list(anchors) if anchors is not None else None
        self.timeout = timeout
        self._bearer = None
        self._bearer_exp = 0.0

    def _urlopen(self, req):
        parsed = urllib.parse.urlsplit(req.full_url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise ValueError("issuer_url must be an http(s) URL, got %r" % (self.issuer_url,))
        return urllib.request.urlopen(req, timeout=self.timeout)  # nosec B310 -- scheme verified to be https or http above

    # --- OAuth2 client-credentials (cached, refreshed on expiry) --------------
    def _access_token(self):
        if self._bearer and time.time() < self._bearer_exp - 5:
            return self._bearer
        creds = base64.b64encode(("%s:%s" % (self.client_id, self.client_secret)).encode()).decode()
        req = urllib.request.Request(
            "%s/api/v1/oauth/token" % self.issuer_url, data=b"grant_type=client_credentials",
            headers={"Authorization": "Basic " + creds,
                     "Content-Type": "application/x-www-form-urlencoded"})
        with self._urlopen(req) as r:
            body = json.loads(r.read())
        self._bearer = body["access_token"]
        self._bearer_exp = time.time() + _expires_in(body.get("expires_in"))
        return self._bearer

    def _online_status(self, cred):
        body = json.dumps({"token_value": cred.get("token_value"),
                           "signature_hex": cred.get("signature_hex")}).encode()
        req = urllib.request.Request(
            "%s/api/v1/verify" % self.issuer_url, data=body,
            headers={"Authorization": "Bearer " + self._access_token(),
                     "Content-Type": "application/json"})
        with self._urlopen(req) as r:
            return json.loads(r.read())

    def verify_presentation(self, presentation) -> Verdict:
        """Decide accept / reject / provisional for a holder's presentation (a
        wallet presentation object, or a bare authenticity pack)."""
        cred = presentation.get("credential") if isinstance(presentation, dict) and "credential" in presentation \
            else presentation
        cred = cred or {}
        a = verify_authenticity(cred, self.anchors)
        reasons = []
        if not a.authentic:
            reasons.append(a.note or "not authentic")
            return Verdict("reject", False, a.issuer_trusted, None, reasons=reasons)
        if a.issuer_trusted is False:
            reasons.append(a.note or "issuer not trusted")
            return Verdict("reject", True, False, None, reasons=reasons)
        if not self.issuer_url:
            reasons.append("status not checked (offline) -- authenticity only, not a full accept")
            return Verdict("provisional", True, a.issuer_trusted, None, reasons=reasons)
        try:
            status = self._online_status(cred)
        except Exception as e:
            reasons.append("status check failed: %s" % e)
            return Verdict("reject", True, a.issuer_trusted, None, reasons=reasons)
        # Only the JSON boolean true. bool() read {} as false and "false" as true, and the
        # TypeScript SDK read both as true (2026-10-01).
        current = status.get("currently_authoritative") is True
        if not current:
            reasons.append("not currently authoritative (revoked/inactive): status=%s" % status.get("status"))
        return Verdict("accept" if current else "reject", True, a.issuer_trusted, current,
                       status=status.get("status"), reasons=reasons or None)


# ---------------------------------------------------------------------------
# P9.3 — the scoped nullifier, for a relying party that enforces one person once.
#
# This SDK cannot verify a Plonky2 proof: that needs the polaris_zk crate, and a
# verifier without it must ABSTAIN rather than guess, which is what the detached
# verifier does. What an SDK integrator DOES need is the one rule that is easy to
# get wrong by hand, so it lives here rather than in prose someone may not read.
# ---------------------------------------------------------------------------

def nullifiers_link(a, b) -> bool:
    """Do two nullifiers name the same person, in the same scope and epoch?

    Exact match on lowercase hex, and nothing else. Three warnings, because each
    is a mistake a relying party can make while believing it is being careful:

    1. Never compare PREFIXES. A nullifier is a Poseidon hash; a shared prefix
       means nothing, and treating it as a partial match would refuse strangers.
    2. Never compare ACROSS SCOPES. Two verifiers' nullifiers for one person are
       uncorrelated by construction. Comparing them cannot return information,
       and a `False` from such a comparison must not be read as "different
       person": the honest answer is that you cannot tell, which is the whole
       point of the scope.
    3. Never carry a ledger ACROSS EPOCHS. The nullifier rotates each epoch so
       that membership does not become a permanent identifier. A ledger that
       outlives its epoch quietly turns the privacy feature into a lifelong one.

    So: key your ledger by (your scope, epoch), keep only the nullifiers, and
    compare with this.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return a.strip(_ASCII_WS).lower() == b.strip(_ASCII_WS).lower()


# ---------------------------------------------------------------------------
# P9.4 — the pairwise handle, for a relying party keying its own records.
# ---------------------------------------------------------------------------

#: The whitespace a pairwise handle or a nullifier is trimmed of: ASCII only. `strip()` also
#: removed a file separator and other Unicode spaces, and JavaScript's `trim()` a byte-order mark,
#: so one scope gave two handles (2026-10-01).
_ASCII_WS = " \t\n\r\x0b\x0c"
_PAIRWISE_TAG = "polaris-pairwise/1"


def pairwise_handle(holder_public_key_hex, verifier_scope):
    """The per-verifier handle to key your records by, instead of the token value.

    `SHA3-256("polaris-pairwise/1|" || holder_public_key_hex || "|" || verifier_scope)`.
    Recompute it yourself from the holder binding you verified; never take the holder's
    word for it.

    What it buys: your stored records cannot be matched against another verifier's. That
    is the realistic threat, because stored values are what get pooled, sold, subpoenaed
    and breached.

    What it does not buy: a plain presentation still SHOWS you a stable token value,
    issuer signature and holder key. Two verifiers who deliberately keep the raw material
    can still correlate. Withholding it needs the zero-knowledge path, where the scoped
    nullifier is the handle. `verify_presentation` in the detached verifier reports which
    of the two applies, under `correlation`; do not assume the stronger one.

    Returns None on unusable input rather than the hash of an empty string, which would
    collide every holder into one record.
    """
    import hashlib as _h
    if not isinstance(holder_public_key_hex, str) or not holder_public_key_hex.strip(_ASCII_WS):
        return None
    if verifier_scope is None or not str(verifier_scope).strip(_ASCII_WS):
        return None
    material = "%s|%s|%s" % (_PAIRWISE_TAG, holder_public_key_hex.strip(_ASCII_WS).lower(),
                             str(verifier_scope).strip(_ASCII_WS))
    return _h.sha3_256(material.encode("utf-8")).hexdigest()


def handles_link(a, b) -> bool:
    """Do two pairwise handles name the same holder at the same verifier?

    Exact hex, and only within one scope. Comparing handles across verifiers is
    meaningless: the values are uncorrelated by construction, so a False cannot be read as
    "different person". Across scopes the honest answer is that you cannot tell.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return a.strip(_ASCII_WS).lower() == b.strip(_ASCII_WS).lower()


# ---------------------------------------------------------------------------
# P9.8 — the delegated agent grant.
#
# A service that an agent acts against needs to decide the chain offline. These are the
# canonical statements; verification is the same two-witness ML-DSA check this SDK already
# does for every other signed artifact.
# ---------------------------------------------------------------------------

_AGENT_GRANT_KEYS = ["format", "grant_id", "agent_public_key_hex", "agent_algorithm", "actions",
                     "limits", "context_id", "issued_at", "expires_at", "algorithm"]
_GRANT_REVOCATION_KEYS = ["format", "grant_id", "revoked_at", "algorithm"]
_AGENT_PROOF_KEYS = ["format", "grant_id", "action", "service_nonce", "issued_at", "algorithm"]


def grant_covers(grant, action) -> bool:
    """Does this grant's signed `actions` list cover the action being requested?

    An absent or empty list grants NOTHING. A verifier that read it as unrestricted would
    turn a grant back into the unbounded credential hand-over that grants exist to replace,
    and the mistake would be invisible because everything would work.
    """
    if not isinstance(grant, dict):
        return False
    actions = grant.get("actions")
    if not isinstance(actions, (list, tuple)) or not actions:
        return False
    # As text on both sides, as the TypeScript SDK reads them: str() spelled true "True" where
    # String() spells it "true", so a signed `actions: [true]` covered "true" in one SDK only
    # (2026-10-01).
    want = _wire_text(action)
    return want is not None and any(_wire_text(a) == want for a in actions)


def grant_within_limits(grant, uses_so_far: int = 0, amount=None):
    """Are the grant's stated limits still satisfied? Returns (ok, note).

    Unknown limit keys are REFUSED, not ignored. A grant that says `max_transfers: 3` to a
    service that has never heard of `max_transfers` must not be treated as unlimited; that
    is how a bounded grant silently becomes an unbounded one.
    """
    # 2026-09-30: a `limits` that was present but not an object (a list, a string, a number)
    # was read as no limits at all, so a signed bounded grant answered as unlimited here and
    # in polaris-verify, while the TypeScript SDK refused a list. Absent means unlimited;
    # anything else that is not an object is a limit this verifier cannot read, and refused.
    if not isinstance(grant, dict):
        return False, "the grant is not an object"
    limits = grant.get("limits")
    if limits is None:
        limits = {}
    elif not isinstance(limits, dict):
        return False, "the grant's limits are not an object; refusing rather than ignoring them"
    unknown = sorted(set(limits) - {"max_uses", "max_amount"})
    if unknown:
        return False, ("the grant carries limits this verifier does not understand (%s); refusing "
                       "rather than ignoring them" % ", ".join(unknown))
    # 2026-09-17: both limits were defeated by a non-finite number. `limits` is inside the
    # SIGNED statement, so a grant signed with `max_amount: NaN` was a signed UNLIMITED grant
    # wearing a limit field: `float(1000000) > float('nan')` is False and the refusal never
    # fired. `json.loads` accepts the bare literal NaN by default, so it arrives off the
    # wire. And `int(float('inf'))` raises OverflowError, which `(TypeError, ValueError)`
    # does not catch, so the infinity case crashed instead of refusing. The docstring
    # promises unknown limits are REFUSED, not ignored; neither branch delivered that.
    #
    # The TypeScript SDK guarded `max_uses` with `Number.isFinite` and not `uses_so_far`, so
    # each SDK had a hole the other did not. Both are closed and the differential test
    # compares them.
    for label, value in (("max_uses", limits.get("max_uses")),
                         ("the use count", uses_so_far),
                         ("max_amount", limits.get("max_amount")),
                         ("the requested amount", amount)):
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return False, ("%s is not a finite number (%r); refusing rather than ignoring "
                           "the limit" % (label, value))
    # Whole numbers, as the TypeScript SDK requires: `int()` read 2.5 uses as 2, so the same
    # signed grant was within its limit here and refused there (2026-10-01).
    if limits.get("max_uses") is not None and (float(limits["max_uses"]) != int(limits["max_uses"])
                                               or float(uses_so_far) != int(uses_so_far)):
        return False, "max_uses and the use count must be whole numbers"
    try:
        if limits.get("max_uses") is not None and int(uses_so_far) >= int(limits["max_uses"]):
            return False, "the grant's use limit (%s) is exhausted" % limits["max_uses"]
        if limits.get("max_amount") is not None and amount is not None \
                and float(amount) > float(limits["max_amount"]):
            return False, "the requested amount exceeds the grant's limit (%s)" % limits["max_amount"]
    except (TypeError, ValueError, OverflowError):
        return False, "a limit or the requested amount is not a number"
    return True, None


def revocation_ends_grant(revocation, grant) -> bool:
    """Does this revocation end THIS grant, and was it signed by the right key?

    Signature verification is the caller's usual `verify_signed_artifact` step; this is the
    binding check that must accompany it. Anyone may publish bytes claiming to revoke a
    grant, but only the holder who signed the grant may end it, so the revocation's signing
    key must equal the grant's.
    """
    if not isinstance(revocation, dict) or not isinstance(grant, dict):
        return False
    if revocation.get("format") != "polaris-grant-revocation/1":
        return False
    # As text, as the TypeScript SDK reads it: str(x or "") matched a revocation naming 0 to a
    # grant naming none, and "True" to true (2026-10-01).
    if not _wire_text_equal(revocation.get("grant_id"), grant.get("grant_id")):
        return False
    return _same_hex(revocation.get("public_key_hex"), grant.get("public_key_hex"))


def grant_principal_bound(grant, binding, credential, now=None) -> bool:
    """Does the key that signed this grant speak for somebody?

    It must be the holder key an ISSUER bound to this credential, under a binding that is
    genuine, fresh and ACTIVE, and the credential's own signature must verify. A revoked binding is published so that a verifier sees the
    holder has no usable key (the lost-device case, where the key is what a thief holds); a
    grant signed with it speaks for nobody. The grant's own signature is the caller's
    `verify_signed_artifact` step.
    """
    if not isinstance(grant, dict) or not isinstance(binding, dict) or not isinstance(credential, dict):
        return False
    if binding.get("format") != "polaris-holder-binding/1":
        return False
    # 2026-09-30: the credential's own signature, the first link WIRE-SPEC 3.17 names. The
    # binding was compared with the credential but the credential was never verified, so a
    # chain signed end to end under an attacker's key, with a credential whose signature
    # does not verify at all, was bound. Whether its issuer is one you trust is the caller's
    # verify_authenticity(credential, anchors).
    if not verify_authenticity(credential).authentic:
        return False
    bv = verify_signed_artifact(binding, now=now)
    # Fresh means CHECKED fresh: a binding with no window, or a `now` that is not an instant, left
    # `fresh` None and `is not False` read it as fresh, so a binding that expired in 2024 was
    # bound (2026-09-30).
    return bool(bv.authentic and bv.fresh is True
                and _status_of(binding) == "active"
                and _same_hex(binding.get("holder_public_key_hex"), grant.get("public_key_hex"))
                and _wire_text_equal(binding.get("token_value"), credential.get("token_value"))
                and _same_hex(binding.get("public_key_hex"), credential.get("public_key_hex")))


#: The largest integer both languages hold exactly. JavaScript reads a larger one as the nearest
#: double, so 2**64 and 2**64 + 1 are one number in the TypeScript SDK and two here.
_MAX_SAFE_INTEGER = 2 ** 53 - 1


def _safe_int(x):
    """An integer, not a boolean, that JavaScript holds exactly."""
    return isinstance(x, int) and not isinstance(x, bool) and abs(x) <= _MAX_SAFE_INTEGER


def _hex_text(x):
    """A hex field (a key or a digest) as both languages compare it: a non-empty string, in lower
    case; anything else None. JavaScript's String() reads a one-element list as its element where
    Python's str() writes the brackets, so a signed `public_key_hex: [K]` matched K in the
    TypeScript SDK alone; and `str(x or "")` read null, 0 and false as one empty key (2026-10-01)."""
    return x.lower() if isinstance(x, str) and x else None


def _same_hex(a, b):
    """Both are hex text and the same in any case; a value with none matches nothing."""
    t = _hex_text(a)
    return t is not None and t == _hex_text(b)


def _hex_in(x, texts):
    """`x` is hex text and one of `texts`; a value with none is in no list, even one holding None."""
    t = _hex_text(x)
    return t is not None and t in texts


def _same_id(a, b):
    """Two agency or context ids name the same one only when both are strings, or both integers
    JavaScript holds exactly, and equal: what the TypeScript SDK's `===` gives on values both
    languages read alike. `==` let a missing id match a null one (None == None) and True match 1,
    where `===` refused both (2026-10-01)."""
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return _safe_int(a) and _safe_int(b) and a == b


def _wire_text(x):
    """A string, or an integer JavaScript holds exactly, as the text the TypeScript SDK's String()
    gives it; anything else None. `str(x or "")` read 0 as missing, and `str()` writes 1.0 as
    "1.0" and True as "True" where String() writes "1" and "true", so a proof naming nonce 0
    failed here and passed there."""
    if isinstance(x, str):
        return x
    if _safe_int(x):
        return str(x)
    return None


def _wire_text_equal(signed, expected):
    """The signed field names the expected value: both have a wire text and it is the same. A
    value with none (absent, null, a boolean, a fraction, a container) matches nothing; compared
    bare, None == None let a proof naming no nonce match an expected nonce of 1.5 (2026-10-01)."""
    t = _wire_text(signed)
    return t is not None and t == _wire_text(expected)


def agent_proof_proves(proof, grant, action=None, nonce=None) -> bool:
    """Is this agent proof bound to THIS grant, this action and this service's nonce?

    Signature verification is the caller's `verify_signed_artifact` step; this is the binding
    that must accompany it, or a copied grant is a bearer token. The proof must name the grant,
    be signed by the agent key the grant names, under the algorithm the HOLDER authorized (the
    proof's own `algorithm` is the agent's unsigned word about itself), and, when the service
    supplies them, name the requested action and the service's nonce (a replay names another).
    """
    if not isinstance(proof, dict) or not isinstance(grant, dict):
        return False
    if proof.get("format") != "polaris-agent-proof/1":
        return False
    if not _wire_text_equal(proof.get("grant_id"), grant.get("grant_id")):
        return False
    if not _same_hex(proof.get("public_key_hex"), grant.get("agent_public_key_hex")):
        return False
    if grant.get("agent_algorithm") is not None and proof.get("algorithm") != grant.get("agent_algorithm"):
        return False
    if nonce is not None and not _wire_text_equal(proof.get("service_nonce"), nonce):
        return False
    if action is not None and not _wire_text_equal(proof.get("action"), action):
        return False
    return True


# --- P8.2: the exchange in use (1.0.0-rc.64) -----------------------------------------
# The exchange artifacts were verified here for their signature and nothing else, while the
# detached verifier answers every question a party holding one has to ask: is it by the
# requester or responder I expected, was the requester attested in this context by an
# authority I trust at the instant I am deciding, and do the bodies I hold match what was
# committed. These three answer the same questions, and answer nothing past authenticity
# for an object its signer did not sign.

@dataclasses.dataclass
class ExchangeRequestVerdict:
    authentic: bool
    requester_matches: Optional[bool] = None
    requester_authorized: Optional[bool] = None
    body_bound: Optional[bool] = None
    note: Optional[str] = None


@dataclasses.dataclass
class ExchangeReceiptVerdict:
    authentic: bool
    responder_matches: Optional[bool] = None
    requester_authorized: Optional[bool] = None
    via: Any = None
    request_bound: Optional[bool] = None
    response_bound: Optional[bool] = None
    #: The responder the receipt names, a SIGNED field, reported only for an authentic receipt.
    responder: Any = None
    note: Optional[str] = None


@dataclasses.dataclass
class ExchangeMintVerdict:
    authentic: bool
    responder_matches: Optional[bool] = None
    note: Optional[str] = None


def _attestation_open(att, now=None) -> bool:
    """The attestation's own window: no `valid_until` is open; an unreadable one is closed."""
    until = att.get("valid_until")
    if until is None:
        return True
    u = _iso_to_epoch(until)
    n = _iso_to_epoch(now) if now is not None else time.time()
    return u is not None and n is not None and u >= n


def _exchange_authorities(key_hex, context_id, manifests, now=None):
    """The authority of every manifest the caller trusts that is genuine and fresh at `now` and
    attests `key_hex` in EXACTLY `context_id`, inside the attestation's own window, in order.
    The section 4 rule, applied to an institution rather than a credential."""
    want = _hex_text(key_hex)
    found = []
    if not want:
        return found
    for m in (manifests if isinstance(manifests, (list, tuple)) else []):
        m = m if isinstance(m, dict) else {}
        mv = verify_signed_artifact(m, now=now)
        if not (mv.authentic and mv.fresh is True):
            continue
        if any(isinstance(att, dict)
               and _hex_text(att.get("attested_public_key_hex")) == want
               and _same_id(att.get("context_id"), context_id)
               and _attestation_open(att, now)
               for att in (m.get("attestations") if isinstance(m.get("attestations"), list) else [])):
            found.append(m.get("authority"))
    return found


def _same_key(a, b) -> bool:
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()


def _sha3_hex(body) -> str:
    raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
    return hashlib.sha3_256(raw).hexdigest()


def verify_exchange_request(envelope, requester_key=None, trusted_manifests=None, body=None,
                            now=None) -> ExchangeRequestVerdict:
    """Verify a requester-signed exchange envelope OFFLINE (wire spec 3.11): the signature,
    under the key the envelope's signed `requester` names; with `requester_key`, that it is
    the requester expected; with `trusted_manifests`, that one of them, genuine and fresh at
    `now`, attests the requester in the envelope's context; with `body`, that `request_hash`
    is the SHA3-256 of the body's canonical JSON."""
    e = envelope if isinstance(envelope, dict) else {}
    if e.get("format") != "polaris-exchange-request/1":
        return ExchangeRequestVerdict(False, note="not a polaris-exchange-request/1")
    req = e.get("requester") if isinstance(e.get("requester"), dict) else {}
    # The key that verifies is the envelope's; it must be the one the SIGNED statement claims
    # for the requester, or a stranger's signature speaks in the requester's name.
    if not _same_key(e.get("public_key_hex"), req.get("public_key_hex")):
        return ExchangeRequestVerdict(False, note="the envelope's key is not the requester it names")
    base = verify_signed_artifact(e, now=now)
    if not base.authentic:
        return ExchangeRequestVerdict(False, note=base.note)
    v = ExchangeRequestVerdict(True)
    if requester_key is not None:
        v.requester_matches = _same_key(e.get("public_key_hex"), requester_key)
    if trusted_manifests is not None:
        v.requester_authorized = bool(_exchange_authorities(e.get("public_key_hex"), e.get("context_id"),
                                                            trusted_manifests, now))
    if body is not None:
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
        v.body_bound = _sha3_hex(canon) == _hex_text(e.get("request_hash"))
    return v


def verify_exchange_receipt(receipt, now=None, trusted_manifests=None, responder_key=None,
                            request_body=None, response_body=None) -> ExchangeReceiptVerdict:
    """Verify a responder-signed exchange receipt OFFLINE (wire spec 3.8): the signature; with
    `responder_key`, that the expected responder signed it (and only then `responder`, the
    responder the receipt names); with `trusted_manifests`, that one
    of them, genuine and fresh at `now`, attests the REQUESTER in exactly the receipt's
    context (a receipt stating no context is not authorized by an attestation from another),
    and which authority (`via`); with a body, that its commitment binds. A receipt commits to
    the SHA3-256 of the body bytes as exchanged, so a body is hashed as given (bytes, or the
    string's UTF-8), not re-serialized."""
    r = receipt if isinstance(receipt, dict) else {}
    if r.get("format") != "polaris-exchange-receipt/1":
        return ExchangeReceiptVerdict(False, note="not a polaris-exchange-receipt/1")
    base = verify_signed_artifact(r, now=now)
    if not base.authentic:
        return ExchangeReceiptVerdict(False, note=base.note)
    v = ExchangeReceiptVerdict(True)
    if responder_key is not None:
        v.responder_matches = _same_key(r.get("public_key_hex"), responder_key)
    # A receipt names its responder in the statement its signer wrote, so the name is the
    # signer's claim until `responder_key` shows the signer IS that responder. Until 2026-09-30 a
    # receipt signed by a stranger reported the victim agency it named as its responder.
    if v.responder_matches is True:
        v.responder = r.get("responder")
    if request_body is not None:
        v.request_bound = _sha3_hex(request_body) == _hex_text(r.get("request_hash"))
    if response_body is not None:
        v.response_bound = _sha3_hex(response_body) == _hex_text(r.get("response_hash"))
    if trusted_manifests is not None:
        req = r.get("requester") if isinstance(r.get("requester"), dict) else {}
        # `via` names the authority, so an attestation in a manifest that names none is no
        # answer to "authorized by whom" (the detached verifier's rule too).
        named = [a for a in _exchange_authorities(req.get("public_key_hex"), r.get("context_id"),
                                                  trusted_manifests, now) if a]
        v.via = named[0] if named else None
        v.requester_authorized = bool(named)
    return v


def verify_exchange_mint(mint, responder_key=None) -> ExchangeMintVerdict:
    """Verify a responder-signed mint statement OFFLINE (wire spec 3.8.1): the signature, and
    with `responder_key`, that the expected responder's key signed it."""
    m = mint if isinstance(mint, dict) else {}
    if m.get("format") != "polaris-exchange-mint/1":
        return ExchangeMintVerdict(False, note="not a polaris-exchange-mint/1")
    base = verify_signed_artifact(m)
    if not base.authentic:
        return ExchangeMintVerdict(False, note=base.note)
    v = ExchangeMintVerdict(True)
    if responder_key is not None:
        v.responder_matches = _same_key(m.get("public_key_hex"), responder_key)
    return v
