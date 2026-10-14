# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""sdjwt.py -- verify an SD-JWT VC presentation with key binding, and refuse precisely.

This is the half of an OpenID4VP verifier that DECIDES. It touches no socket, reads no
configuration file and knows nothing about HTTP: give it the `~`-separated presentation a
wallet sent, the nonce and audience the request asked for, and the keys the issuer is trusted
under, and it returns a verdict. Everything about transport lives next door in `verifier.py`.

WHY THE REFUSALS ARE THE POINT. The OpenID Foundation conformance suite's HAIP verifier plan
is eleven modules for SD-JWT VC, and SEVEN of them are negative: the wallet sends a
presentation that is broken in one specific way and the verifier has to reject it. Those seven
are scored automatically, on a 4xx, with no human in the loop. So this file is written as a
list of the ways a presentation can be wrong, each with its own reason string, and every one
of them has a test that builds exactly that breakage and watches it get caught.

The seven, and where each is caught:

    invalid-credential-signature   the issuer JWS does not verify           -> issuer_signature
    invalid-sd-hash                sd_hash != SHA-256 of what was presented -> sd_hash
    invalid-kb-jwt-signature       the KB-JWT does not verify under cnf.jwk -> kb_signature
    invalid-kb-jwt-nonce           nonce is not the one we asked for        -> nonce
    invalid-kb-jwt-aud             aud is not us                            -> audience
    kb-jwt-iat-in-past             KB-JWT minted 365 days ago               -> kb_freshness
    kb-jwt-iat-in-future           KB-JWT minted 365 days ahead             -> kb_freshness

Reference: draft-ietf-oauth-selective-disclosure-jwt, draft-ietf-oauth-sd-jwt-vc, and
OpenID4VP 1.0 section 8. Measured against the suite rather than read off them alone: the
issuer JWT's `typ` is `dc+sd-jwt`, the key binding JWT's is `kb+jwt`, and `sd_hash` is the
base64url SHA-256 of the US-ASCII bytes of everything up to and including the final `~`.
"""
import base64
import binascii
import datetime
import hashlib
import json
import math
import threading
import time
import urllib.parse

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography import x509
    from cryptography.x509 import load_der_x509_certificate
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised by the import-failure path only
    _HAVE_CRYPTO = False

#: How far a key binding JWT's `iat` may be from now, in seconds. The two conformance
#: modules that attack this use a year in each direction, so anything sane catches them; the
#: number is here because a verifier with NO window accepts a replayed presentation forever,
#: which is the failure the `iat` claim exists to prevent.
DEFAULT_MAX_SKEW_SECONDS = 300

#: The only `typ` the profile mints. A presentation that says something else is not a thing
#: this verifier knows how to check, and guessing is how a verifier accepts the wrong format.
#: `vc+sd-jwt`, the typ SD-JWT VC used before it was renamed, now names a W3C VC Data Model
#: 2.0 credential secured with SD-JWT (VC-JOSE-COSE), which ends in `validUntil` and is
#: revoked through `credentialStatus`; this verifier reads neither, so it refuses that typ.
ISSUER_TYP = "dc+sd-jwt"
KB_TYP = "kb+jwt"

#: ES256 only, which is HAIP's floor and its ceiling for the mandatory set. Naming the
#: algorithm in a list rather than reading it out of the header is deliberate: `alg` is
#: attacker-controlled, and a verifier that follows it can be walked down to `none`.
ACCEPTED_ALGS = ("ES256",)

#: Claims no disclosure may supply. SD-JWT VC draft 19, section 2.2.2.3: "The following
#: registered JWT claims, including any of their sub-claims, when used in the SD-JWT component
#: of an SD-JWT VC, MUST NOT be included in Disclosures and therefore MUST NOT be selectively
#: disclosed": iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts and status. The same section
#: lists the two that "MAY be included in Disclosures": sub and iat.
#:
#: A rule about WHERE a disclosure lands, not what it is called. A registered claim is a member
#: of the payload's top level, so a disclosure is refused when it supplies one of these there, or
#: anything inside one: a sub-claim of `status`, an element of `aka_vcts`, a member of `cnf`. A
#: private claim further down that shares a name, `degree.status` or `vehicle.exp`, is not the
#: registered claim and is disclosed like any other. Until 2026-10-10 this was a list of names
#: matched at every depth, with `iat` on it and neither `vct#integrity` nor `aka_vcts`, so it
#: refused conforming credentials (a disclosed `iat`, the two private claims above) and accepted
#: non-conforming ones (a disclosed `vct#integrity`, `aka_vcts` or sub-claim of `status`).
#:
#: Refusing these rather than only a collision is the stronger rule and the necessary one. A
#: collision check alone catches a disclosure that overwrites `iss`, and misses one that
#: INTRODUCES `exp` where the issuer set none, which puts a holder-chosen expiry into the claims
#: a relying party reads. `cnf` is the sharpest: a disclosed `cnf` returns a key that is not the
#: key the key binding was checked against, whether or not the issuer set one. Measured
#: 2026-09-17; every one of these verified as authentic before.
_NEVER_DISCLOSED = frozenset(
    ("iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"))

#: Names SD-JWT keeps for its own structure, refused as a disclosure's claim name at any depth:
#: RFC 9901 section 7.1 rejects a disclosure named `_sd` or `...`, and section 4.1.1 keeps
#: `_sd_alg` to the payload's top level.
_RESERVED_DISCLOSURE_NAMES = frozenset(("_sd", "_sd_alg", "..."))

#: Bounds on hostile input. There were none anywhere in this package until 2026-09-17: a
#: 117 MiB presentation with a two-million-entry `_sd` array verified as authentic in 1.46 s,
#: having built a two-million-element set on the way there.
#:
#: The sizes are generous next to anything real. The capture from the hosted conformance
#: suite is under 8 KB with eleven committed claims; 256 KiB of presentation and 64 KiB of
#: any single JSON document leave several orders of margin.
MAX_PRESENTATION_BYTES = 256 * 1024
MAX_JSON_BYTES = 64 * 1024
MAX_DISCLOSURES = 512

#: How deep a JSON document may nest, and how deep the disclosure resolver may recurse.
#: `json.loads` is recursive with no limit of its own, and CPython's default recursion limit
#: is around 1000 frames, so 994 levels of `[` raised RecursionError out of a function
#: documented never to raise. 64 is deeper than any credential shape in the specification.
MAX_JSON_DEPTH = 64
MAX_RESOLVE_DEPTH = 64

#: Extended key usages an issuer certificate may carry. A certificate that states EKUs and
#: names none of these is saying what it is for, and it is not this.
#:
#: 1.0.18013.5.1.2 is ISO/IEC 18013-5's document signer (id-mdl-kp-mdlDS), the usage EUDI
#: credential issuers put on their signing certificates. Until 2026-09-30 it was missing, and
#: eudi-dev's PID Provider certificate (critical EKU = that OID, digitalSignature, under its
#: own CA) was refused as "does not chain to any configured trust anchor": the first
#: credential here signed by an issuer this repository did not write was refused for naming
#: exactly the purpose it is for.
#:
#: 1.3.130.2.0.0.1.2 is id-eudi-iso-pid-kp-DS, "for document signer certificates, used by PID
#: Providers": the EUDI Wallet ARF's PID Rulebook (Annex 3.1, section 3.2.1, in ARF 1.4.0 and
#: 1.4.1) defines it as {id-eudi-iso-pid-kp 2} under european-commission(130), for PIDs in the
#: ISO/IEC 18013-5 format, and notes the arc "will have to be officially registered"; ARF 1.5.0
#: removed the section. The EU reference PID issuer (eudi-srv-web-issuing-eudiw-py) signs its
#: SD-JWT VCs with its configured document signer's certificate in `x5c`, and the test
#: document-signer certificates it publishes carry this OID, critical and alone (PID-DS-0002 and
#: PID-DS-0003 are in testdata/eudi-pid-ds/). Until 2026-10-10 they were refused here.
if _HAVE_CRYPTO:
    _ISSUER_EKUS = frozenset((
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
        x509.ObjectIdentifier("1.0.18013.5.1.2"),
        x509.ObjectIdentifier("1.3.130.2.0.0.1.2"),
    ))
else:  # pragma: no cover
    _ISSUER_EKUS = frozenset()

#: How many certificates an issuer's `x5c` may carry: the signing certificate and up to three CA
#: certificates between it and a configured trust anchor. RFC 7515 4.1.6 orders the array, each
#: certificate certifying the one before it, so the chain is checked as sent, link by link, and
#: nothing is searched for. Until 2026-10-03 only the leaf was read: eudi-dev v2.5.0's PID
#: Provider signs under an intermediate CA that it sends as `x5c[1]`, and was refused.
MAX_X5C_CERTS = 4


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class Verdict:
    """Authentic or not, and if not, exactly which check said so.

    `authentic` is a statement about the SIGNATURE and the presentation: the issuer signed
    this, the disclosures match what was signed, the holder proved possession, it is inside
    its own validity window. It has never been a statement about revocation and is not one
    now.

    `revocation` is that second question, added 2026-09-19 because until then the verdict did
    not carry it in any form. An SD-JWT VC's `status` claim is issuer-signed and MUST NOT be
    selectively disclosable, so a credential that carries one is telling every verifier where
    its revocation list lives. This verifier parsed that claim, protected it, handed it back
    inside `claims`, and said nothing about it, so a relying party reading `authentic: true`
    was being told the strongest thing this code can say while the second question went
    unasked and unmentioned.

    Silence is the problem, not the absence of a fetch. Saying what was not established costs
    nothing and is the difference between a bounded claim and an overstated one.

    Asking is opt-in, and stays that way. `verify_presentation(..., status_resolver=...)`
    takes a callable the relying party supplies; `polaris_oid4vp.status` decides the token
    once they have it. The default is unchanged and the default is honest: no resolver means
    `not_evaluated`, which is what this package can say about a list it did not read.

    Opt-in rather than automatic because a status check is a network call with a timeout, a
    cache and an availability coupling to somebody else's server, and what a slow or failed
    check should cost is a policy only the relying party can set. A verifier library that
    made that call for them would be choosing, silently, that their traffic stops when a
    third party's endpoint does.

    WHO SIGNED, when the key came from an `x5c` leaf (added 2026-10-10; each is None for a
    configured JWK and for a refusal). With `x5c` the issuer is the leaf's subject under the
    anchor it chained to (SD-JWT VC section 2.5), and `iss` is a name for it only when the leaf
    gives that name:

        issuer_subject  the leaf's subject, RFC 4514
        issuer_anchor   the subject of the configured trust anchor its chain ended at, RFC 4514
        iss_bound       True: `iss` is a name the leaf gives (a URI subjectAltName, or an https
                        URL on a DNS one). False: the leaf gives no such name, so nothing binds
                        `iss` to the key; it is then left out of `claims` and is not handed to
                        the status resolver, and `unbound_iss` carries it. None: no `iss`.
        unbound_iss     the credential's `iss` when `iss_bound` is False, else None

    A leaf that names an issuer other than `iss` is refused (`issuer_key`), as before. Every
    other field means what it meant: `claims["iss"]`, when present, is the issuer that signed.
    Unbound iss: delegated status lists are not consulted; status is established only by a list
    signed with the credential's own key. (`status.StatedAuthority` is keyed by issuer, and the
    resolver is given None.)

    A WALLET'S ERROR RESPONSE (added 2026-10-11) is not a presentation and is never authentic:
    `Verifier` answers one 200 and returns a verdict with code `wallet_error`, no claims, and
    `wallet_error` holding what the response said (None on every other verdict):

        error              its `error` (OpenID4VP 1.0 section 8.5): 1 to 64 letters, digits or
                           underscores, the shape of every code RFC 6749 and OpenID4VP define
        error_description  its `error_description` as printable ASCII without `<`, cut to 200
                           characters, or None
        state              the outstanding request it names
        encrypted          True: it arrived encrypted to that request's key; False: in the
                           clear (section 8.3.1). Neither says who sent it, since the key and
                           the state are both in the request, and neither closes the request
    """

    __slots__ = ("authentic", "code", "reason", "claims", "revocation", "disclosed",
                 "issuer_subject", "issuer_anchor", "iss_bound", "unbound_iss", "transaction_data",
                 "wallet_error", "response_code")

    def __init__(self, authentic, code="", reason="", claims=None, revocation=None,
                 disclosed=None, issuer_subject=None, issuer_anchor=None, iss_bound=None,
                 unbound_iss=None, transaction_data=None, wallet_error=None):
        self.authentic = authentic
        self.code = code
        self.reason = reason
        self.claims = claims or {}
        self.revocation = revocation
        # The path of every claim a disclosure supplied: object keys, and list positions for
        # array elements. What the issuer signed in clear text is not among them. A verifier
        # reads it to hold a wallet to OpenID4VP 1.0 section 6.4 (see Verifier).
        self.disclosed = frozenset(disclosed or ())
        self.issuer_subject = issuer_subject
        self.issuer_anchor = issuer_anchor
        self.iss_bound = iss_bound
        self.unbound_iss = unbound_iss
        # What the key binding JWT was held to for the request's transaction_data, when the
        # request carried any: which entries it had to bind and under which reading, the hash
        # algorithm it used and its `jti`. None when the request carried none.
        self.transaction_data = transaction_data
        # A wallet's error response, as `Verifier` recorded it (see above). None otherwise.
        self.wallet_error = wallet_error
        # The fresh value `Verifier` put in an accepted response's redirect_uri (OpenID4VP 1.0
        # section 8.2), redeemable once with `Verifier.redeem`. None on every other verdict, and
        # never in `as_dict`, so it does not end up in a log.
        self.response_code = None

    def __repr__(self):
        if self.authentic:
            return "Verdict(authentic, %d claim(s), revocation=%s)" % (
                len(self.claims), (self.revocation or {}).get("state", "n/a"))
        return "Verdict(refused, %s: %s)" % (self.code, self.reason)

    def as_dict(self):
        out = {"authentic": self.authentic, "code": self.code, "reason": self.reason,
               "claims": self.claims, "revocation": self.revocation,
               "issuer_subject": self.issuer_subject, "issuer_anchor": self.issuer_anchor,
               "iss_bound": self.iss_bound, "unbound_iss": self.unbound_iss}
        # Only when there is one, so a verdict on a request without transaction_data has the
        # same members it always had.
        if self.transaction_data is not None:
            out["transaction_data"] = self.transaction_data
        if self.wallet_error is not None:
            out["wallet_error"] = self.wallet_error
        return out


#: The three states a relying party has to be able to tell apart. A verifier that collapses
#: any two of them is overstating one of them.
NO_STATUS_CLAIM = "no_status_claim"        # the credential points at no revocation list
NOT_EVALUATED = "not_evaluated"            # it points at one and nobody was asked to read it
UNSUPPORTED_STATUS = "unsupported_status"  # it points at one in a form this code cannot read
CHECKED = "checked"                        # a resolver answered; `status` carries what it said
UNREACHABLE = "unreachable"                # a resolver was asked and could not answer
NO_AUTHORITY = "no_authority"              # no key is stated as entitled to publish it; nothing was fetched
LIST_REFUSED = "list_refused"              # a list was obtained and is not usable as evidence; `code` says why

#: NOT_EVALUATED and UNREACHABLE are the pair most worth keeping apart, and the easiest to
#: merge by accident. The first says nobody looked. The second says somebody looked and the
#: answer did not come back. A relying party that treats them the same has decided, without
#: being asked, that an unreachable status endpoint is as good as a credential whose issuer
#: publishes none.


def _revocation_state(payload, resolver=None, issuer=None):
    """What this verifier can say about revocation.

    `issuer` is what the resolver is told the issuer is: the credential's `iss` when something
    binds it to the signing key, else None. An `iss` an x5c leaf does not bind is a claim, and a
    resolver keyed by issuer (`status.StatedAuthority` is) must not read a list under it.

    Reads the credential's own issuer-signed `status` claim. With no resolver it opens no
    socket and never answers "not revoked", and the state it returns says so, because a
    caller that cannot distinguish "the issuer published no revocation list" from "there is
    one and nobody looked" cannot make a decision about either.

    A `resolver` is how a relying party opts in to actually asking. It is theirs, not this
    package's, because checking status is a network call with a timeout, a cache and an
    availability coupling, and what a slow or failed check should cost is a policy only they
    can set. `polaris_oid4vp.status` decides the token once they have it.

    The resolver's exceptions are caught and become `unreachable`. A verifier that dies on
    one credential has failed open for every other credential in the queue, and a relying
    party's resolver is ordinary application code reaching a third party's server.
    """
    status = payload.get("status")
    if status is None:
        return {"state": NO_STATUS_CLAIM, "checked": False, "uri": None, "idx": None,
                "reason": "the credential names no revocation list, so there is none to read"}
    if not isinstance(status, dict):
        return {"state": UNSUPPORTED_STATUS, "checked": False, "uri": None, "idx": None,
                "reason": "the credential's status claim is %r, which this verifier cannot "
                          "read; it is not evidence that the credential is current"
                          % type(status).__name__}
    ref = status.get("status_list")
    if isinstance(ref, dict) and isinstance(ref.get("uri"), str) \
            and isinstance(ref.get("idx"), int) and not isinstance(ref.get("idx"), bool):
        if resolver is None:
            return {"state": NOT_EVALUATED, "checked": False,
                    "uri": ref["uri"], "idx": ref["idx"],
                    "reason": "the credential names a Token Status List at %s index %d. This "
                              "verifier did not fetch it, so whether the issuer has revoked "
                              "this credential is UNKNOWN, not false"
                              % (ref["uri"], ref["idx"])}
        try:
            answer = resolver(uri=ref["uri"], idx=ref["idx"], issuer=issuer)
        except Exception as exc:
            return {"state": UNREACHABLE, "checked": False,
                    "uri": ref["uri"], "idx": ref["idx"],
                    "reason": "resolving the status of %s index %d raised %s: %s. That is "
                              "the ABSENCE of an answer, not a negative one"
                              % (ref["uri"], ref["idx"], type(exc).__name__, exc)}
        if not isinstance(answer, dict) or "checked" not in answer:
            return {"state": UNREACHABLE, "checked": False,
                    "uri": ref["uri"], "idx": ref["idx"],
                    "reason": "the status resolver returned %s rather than a verdict, so "
                              "nothing was established about revocation"
                              % type(answer).__name__}
        out = dict(answer)
        if answer.get("checked"):
            out.setdefault("state", CHECKED)
        else:
            # status.py's outcomes stay apart: a missing statement of who may publish, or a
            # list that was obtained and refused, is not a network failure, and a relying party
            # that treats `unreachable` as an outage must not be told one happened.
            code = answer.get("code")
            out.setdefault("state", NO_AUTHORITY if code == NO_AUTHORITY
                           else UNREACHABLE if code in (None, UNREACHABLE) else LIST_REFUSED)
        out["uri"], out["idx"] = ref["uri"], ref["idx"]
        return out
    return {"state": UNSUPPORTED_STATUS, "checked": False, "uri": None, "idx": None,
            "reason": "the credential carries a status claim in a form this verifier does not "
                      "recognise, so its revocation state is unknown"}


def _refuse(code, reason):
    return Verdict(False, code, reason)


# --------------------------------------------------------------------------- encoding

def b64u_decode(value):
    """Decode base64url without padding. Raises ValueError on anything malformed.

    Only the CANONICAL encoding is accepted (2026-09-25). The last character of a base64url
    string carries padding bits that a lenient decoder ignores, so the key binding JWT's
    signature, which nothing else hashes, verified in sixteen spellings: the same signature
    bytes, sixteen different presentations. Replay is refused per nonce, so this opened no
    replay, but a verifier should accept exactly the bytes it checked and nothing that merely
    decodes to them. RFC 7515 base64url has one encoding for given bytes; this requires it."""
    if isinstance(value, str):
        value = value.encode("ascii", "strict")
    pad = -len(value) % 4
    try:
        raw = base64.urlsafe_b64decode(value + b"=" * pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not base64url: %s" % exc) from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=") != value:
        raise ValueError("not canonical base64url: the input carries characters or padding "
                         "bits that its bytes do not")
    return raw


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _digest(disclosure_b64):
    """The digest a payload refers to a disclosure by: base64url(SHA-256(ascii(the b64))).

    Over the ENCODED disclosure, not the decoded JSON. Hashing the decoded form would make
    two different encodings of the same claim collide, which is how a presentation gets to
    swap a disclosure for one the issuer never signed.
    """
    return b64u_encode(hashlib.sha256(disclosure_b64.encode("ascii")).digest())


# ------------------------------------------------------------------------------- JOSE

def _nesting_depth(raw):
    """The deepest bracket nesting in a JSON document, ignoring brackets inside strings.

    A linear scan, so it costs nothing next to the parse it guards. It exists because
    `json.loads` is recursive with no depth limit of its own: 2,780 bytes of `[[[[...]]]]`
    raised RecursionError straight out of this verifier, and RecursionError is not a
    ValueError, so every `except (ValueError, json.JSONDecodeError)` in this file missed it.
    Measured 2026-09-17; the minimum depth that did it was 994.

    Catching RecursionError would be the wrong repair. It fires at an arbitrary point that
    depends on how much stack the caller had already used, so the same input accepted in one
    call site raises in another, and an interpreter that has just unwound a stack overflow is
    not a good place to be making security decisions. Refusing the shape before parsing is
    deterministic.
    """
    depth = maximum = 0
    in_string = escaped = False
    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > maximum:
                maximum = depth
        elif ch in "]}":
            depth -= 1
    return maximum


def _json_bounded(raw, what, unique_keys=False):
    """`json.loads` with the two bounds it has none of: size and nesting depth.

    `unique_keys` also refuses an object that names a member twice, which `json.loads` settles
    silently by keeping the last. Off by default, so every existing caller parses as before."""
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("the %s is %d bytes, over the %d byte limit"
                         % (what, len(raw), MAX_JSON_BYTES))
    text = raw.decode("utf-8", "strict") if isinstance(raw, bytes) else raw
    if _nesting_depth(text) > MAX_JSON_DEPTH:
        raise ValueError("the %s nests deeper than %d levels" % (what, MAX_JSON_DEPTH))
    # `parse_constant` is the other half. Python's json accepts the bare literals NaN,
    # Infinity and -Infinity by default, and they are floats, so they walk past every
    # `isinstance(x, (int, float))` guard downstream. A NaN `iat` defeated the key binding
    # freshness window outright before this. Nothing in JSON proper produces them and no
    # honest wallet emits them, so they are refused at the door rather than guarded against
    # one field at a time.
    def _no_constants(name):
        raise ValueError("the %s contains the non-JSON literal %s" % (what, name))
    if not unique_keys:
        return json.loads(text, parse_constant=_no_constants)

    def _one_of_each(pairs):
        seen = set()
        for name, _ in pairs:
            if name in seen:
                raise ValueError("the %s names the member %r more than once" % (what, name))
            seen.add(name)
        return dict(pairs)
    return json.loads(text, parse_constant=_no_constants, object_pairs_hook=_one_of_each)


def _parse_jws(token):
    """Split a compact JWS into (header, payload, signing_input_bytes, signature_bytes)."""
    if not isinstance(token, str):
        raise ValueError("a compact JWS is a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("a compact JWS has three dot-separated parts, this has %d" % len(parts))
    header = _json_bounded(b64u_decode(parts[0]), "JWS header")
    payload = _json_bounded(b64u_decode(parts[1]), "JWS payload")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWS header and payload must both be JSON objects")
    return header, payload, (parts[0] + "." + parts[1]).encode("ascii"), b64u_decode(parts[2])


def _es256_public_key(jwk):
    """A P-256 public key from a JWK. Rejects anything that is not one."""
    if not isinstance(jwk, dict):
        raise ValueError("a JWK must be a JSON object")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("expected an EC P-256 JWK, got kty=%r crv=%r"
                         % (jwk.get("kty"), jwk.get("crv")))
    # `jwk["x"]` raised KeyError and `b64u_decode(1)` raised TypeError, both straight out of
    # a verifier documented never to raise. Two ways in: an operator's own --issuer-jwks
    # file with a typo in it, and the issuer-signed `cnf.jwk`, which an attacker controls if
    # they control an issuer. Measured 2026-09-17.
    for field in ("x", "y"):
        if not isinstance(jwk.get(field), str):
            raise ValueError("the JWK has no string %r coordinate" % field)
    x = b64u_decode(jwk["x"])
    y = b64u_decode(jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("P-256 coordinates must be 32 bytes each")
    numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"),
                                            int.from_bytes(y, "big"), ec.SECP256R1())
    return numbers.public_key()


def _verify_es256(public_key, signing_input, signature):
    """True if the raw r||s signature is valid. Never raises on a bad signature.

    The key type is checked first, and that was missing. `_chains_to` accepted any leaf the
    anchor had signed, so an RSA certificate from the configured anchor reached here and
    `RSAPublicKey.verify()` was called with ECDSA arguments: TypeError out of the verifier
    rather than a refusal. Anyone holding an RSA certificate from that CA could do it.
    """
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return False
    if not isinstance(public_key.curve, ec.SECP256R1):
        return False
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der = asym_utils.encode_dss_signature(r, s)
    try:
        public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _not_an_es256_verification_key(jwk):
    """True when a JWK says it is for something other than verifying ES256 signatures (RFC 7517
    4.2 to 4.4): a `use` other than "sig", `key_ops` without "verify" or with an operation beside
    "sign" and "verify" (4.3 permits that pair and no other mix), or an `alg` other than ES256.
    An issuer's JWK Set often lists its encryption key beside its signing key, and until
    2026-10-01 every configured P-256 key was a candidate, so an issuer signature verified under
    the key the issuer publishes for encryption."""
    if "use" in jwk and jwk["use"] != "sig":
        return True
    ops = jwk.get("key_ops")
    if "key_ops" in jwk and not (isinstance(ops, list) and "verify" in ops
                                 and all(op in ("sign", "verify") for op in ops)):
        return True
    return "alg" in jwk and jwk["alg"] != "ES256"


def _issuer_public_keys(header, issuer_jwks, trust_anchors, now=None):
    """(keys, reason, certified): the keys the issuer JWS may be checked under, or why there
    are none, and for an x5c key the pair (leaf, anchor) it came from, the anchor being the
    configured one its chain ended at (None for configured JWKs).

    Two ways, both explicit: an `x5c` chain whose leaf chains to a configured trust anchor,
    or JWKs the caller configured out of band. A verifier that takes the key from the token
    without either is not verifying anything, so there is no third way and no fallback: an
    `x5c` that is present decides the way even when it is empty or not a list, and is then
    refused. Every configured JWK that could be the signer is a candidate, because
    `--issuer-jwks` trusts every key it lists; a `kid` that the header and a key both carry,
    and that differs, rules that key out.
    """
    if "x5c" in header:
        chain = header["x5c"]
        if not isinstance(chain, list) or not chain:
            return [], "x5c is present but is not a non-empty array", None
        if len(chain) > MAX_X5C_CERTS:
            return [], ("x5c carries %d certificates; at most %d are read, the signing certificate "
                        "and %d CAs" % (len(chain), MAX_X5C_CERTS, MAX_X5C_CERTS - 1)), None
        try:
            leaf = load_der_x509_certificate(base64.b64decode(chain[0]))
        except Exception as exc:  # noqa: BLE001  any parse failure is the same refusal
            return [], "the x5c leaf certificate does not parse: %s" % exc, None
        intermediates = []
        for position, item in enumerate(chain[1:], start=1):
            try:
                intermediates.append(load_der_x509_certificate(base64.b64decode(item)))
            except Exception as exc:  # noqa: BLE001  any parse failure is the same refusal
                return [], "x5c certificate %d does not parse: %s" % (position, exc), None
        if not trust_anchors:
            return [], ("the credential presents an x5c chain and no trust anchor is "
                        "configured, so nothing can be said about who signed it"), None
        why = _not_an_issuer_leaf(leaf)
        if why:
            return [], why, None
        why = _an_anchor_in_the_chain(intermediates, trust_anchors)
        if why:
            return [], why, None
        for anchor in trust_anchors:
            why = _chains_to(leaf, anchor, now, intermediates)
            # "" chains, a string refuses, and anything else, None or a boolean from the contract
            # this replaced among them, is no chain: an answer of the wrong type fails closed.
            if not isinstance(why, str):
                continue
            # After the chain, so that this refusal names the extended key usage. Inside
            # `_chains_to` it read "does not chain to any configured trust anchor" for a
            # leaf the anchor had certified (the EU reference PID issuer's, until 2026-10-10).
            why = why or _leaf_eku_refusal(leaf)
            if why:
                return [], why, None
            return [leaf.public_key()], "", (leaf, anchor)
        return [], "the x5c leaf does not chain to any configured trust anchor", None
    if issuer_jwks:
        kid = header.get("kid")
        # 2026-09-30: an empty `kid` ruled nothing out, so `"kid": ""` matched a key listed
        # under any name. A `kid` that is present is a name (RFC 7515 4.1.4) or it is refused,
        # as an `x5c` that is present but empty is.
        if "kid" in header and (not isinstance(kid, str) or not kid):
            return [], "kid is present but is not a non-empty string", None
        keys, other_use, not_p256 = [], 0, 0
        for jwk in issuer_jwks:
            # A configured JWK list is operator input and can hold anything. Reading `kid`
            # off a string raised AttributeError straight out of a function whose contract
            # says it never raises on bad input, which on the wire is a broken connection
            # where a 4xx belongs.
            if not isinstance(jwk, dict):
                continue
            if kid and jwk.get("kid") and jwk["kid"] != kid:
                continue
            if _not_an_es256_verification_key(jwk):
                other_use += 1
                continue
            try:
                keys.append(_es256_public_key(jwk))
            except ValueError:
                not_p256 += 1
                continue
        if keys:
            return keys, "", None
        if other_use or not_p256:
            return [], ("no configured issuer JWK that matches this credential's kid can verify it: "
                        + ", ".join(why for n, why in (
                            (other_use, "%d marked for another use by use, key_ops or alg" % other_use),
                            (not_p256, "%d not a P-256 key" % not_p256)) if n)), None
        return [], "no configured issuer JWK matches this credential's kid", None
    return [], ("the credential carries no x5c and no issuer JWK is configured, so there "
                "is no key to check the issuer signature against"), None


def _not_an_issuer_leaf(leaf):
    """"" when an x5c leaf can be an issuer's signing certificate, else why it cannot.

    HAIP 1.0 section 6.1.1: the trust anchor's certificate MUST NOT be in the credential's
    `x5c`, and the certificate that signs it MUST NOT be self-signed. A self-signed leaf is
    an anchor however it is presented, and a leaf that carries its anchor's own key verifies
    under that key too, so the one test covers both. A CA certificate is not an issuer's
    signing certificate either: accepted as a leaf, it lets every sub-CA a registered anchor
    ever certified sign credentials directly. All three verified until 2026-10-01.
    """
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return "the x5c leaf is a CA certificate, not an issuer's signing certificate"
    except x509.ExtensionNotFound:
        pass
    except Exception:  # noqa: BLE001  a malformed extension is not a usable statement
        return "the x5c leaf's basic constraints do not parse"
    if not _self_signed(leaf):
        return ""
    return ("the x5c leaf is self-signed, so it is a trust anchor and not an issuer's "
            "certificate (HAIP 1.0 6.1.1)")


def _self_signed(cert):
    """True when `cert` verifies under its own key, which is what an anchor's certificate does."""
    try:
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                 ec.ECDSA(cert.signature_hash_algorithm))
    except Exception:  # noqa: BLE001  not signed by its own key
        return False
    return True


def _signed_by(child, parent):
    """True when `parent`'s key verifies `child`'s signature and `child` names `parent` as its
    issuer."""
    try:
        parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
                                   ec.ECDSA(child.signature_hash_algorithm))
    except Exception:  # noqa: BLE001  wrong key, wrong algorithm, malformed: all one answer
        return False
    return child.issuer == parent.subject


def _outside_validity(cert, now, what):
    """"" when `now` (an aware datetime) is inside `cert`'s validity period, else a refusal that
    names `what` the certificate is and the period it is valid for."""
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if not_before <= now <= not_after:
        return ""
    return "%s is outside its validity period (%s to %s)" % (
        what, not_before.strftime("%Y-%m-%dT%H:%M:%SZ"), not_after.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _an_anchor_in_the_chain(intermediates, trust_anchors):
    """"" when no CA certificate sent after the leaf is a trust anchor, else which one is.

    HAIP 1.0 6.1.1 keeps the trust anchor's certificate out of `x5c`. A self-signed certificate is
    an anchor however it is sent, and so is one that carries a configured anchor's key.
    """
    der = serialization.Encoding.DER
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    anchor_keys = set()
    for anchor in trust_anchors:
        try:
            anchor_keys.add(anchor.public_key().public_bytes(der, spki))
        except Exception:  # noqa: BLE001  an anchor whose key does not serialise matches nothing
            continue
    for position, ca in enumerate(intermediates, start=1):
        try:
            key = ca.public_key().public_bytes(der, spki)
        except Exception:  # noqa: BLE001
            return "x5c certificate %d has a public key that does not parse" % position
        if key in anchor_keys or _self_signed(ca):
            return ("x5c certificate %d is a trust anchor, and HAIP 1.0 6.1.1 keeps the anchor "
                    "out of x5c" % position)
    return ""


def _may_certify(ca, below):
    """True when `ca`, sent in `x5c`, may certify a path with `below` CA certificates under it.
    Its validity period is read by `_chains_to`, so that a refusal for it says so.

    RFC 5280: a CA certificate asserts basicConstraints cA (4.2.1.9) and, when it states a key
    usage, keyCertSign (4.2.1.3); its pathLenConstraint bounds the CAs beneath it; and a critical
    extension that this code does not read refuses the certificate (4.2). An extended key usage
    that names purposes must admit an issuer's, as the leaf's must.
    """
    try:
        constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            return False
        if constraints.path_length is not None and below > constraints.path_length:
            return False
        try:
            if not ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                return False
        except x509.ExtensionNotFound:
            pass
        try:
            oids = set(ca.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
            if (x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in oids
                    and not oids & _ISSUER_EKUS):
                return False
        except x509.ExtensionNotFound:
            pass
        read = (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage)
        if any(ext.critical and not isinstance(ext.value, read) for ext in ca.extensions):
            return False
    except Exception:  # noqa: BLE001  absent or malformed basic constraints: not a CA
        return False
    return True


def _chains_to(leaf, anchor, now=None, intermediates=()):
    """Is `leaf` certified by `anchor`, directly or through the CA certificates `intermediates`
    that its `x5c` sends after it, and valid at `now` (POSIX seconds; None for the clock)?

    "" when it is. None when the path does not lead to `anchor`: a link that does not verify, a
    CA certificate that may not certify what is beneath it, or more CAs than a path length
    allows. Otherwise, for a path `anchor` does certify, why it is refused: a certificate in it
    outside its validity period, or a leaf whose key usage does not permit signing. Each of those
    read "does not chain to any configured trust anchor" until 2026-10-10, which sent an
    integrator to the trust configuration when a certificate's dates or usage were the answer.

    The chain is checked as sent and nothing is searched for: RFC 7515 4.1.6 has each
    certificate certify the one before it, so every link is the next certificate in the array
    and the last is the anchor. A path builder is a different piece of software with its own
    failure modes. Until 2026-10-03 this was one link only, because the conformance profile
    registers the anchor out of band and sends the leaf alone; eudi-dev v2.5.0's PID Provider
    sends its leaf and the intermediate CA that signed it.
    """
    path = [leaf, *intermediates]
    for child, parent in zip(path, path[1:] + [anchor]):
        if not _signed_by(child, parent):
            return None

    # 2026-09-17: the signature and the issuer/subject match were the WHOLE check, and that
    # is not a trust decision, it is a "did this CA ever sign this" decision. Three things
    # were measured passing that should not have:
    #
    #   a leaf whose not_valid_after was yesterday
    #   a leaf whose not_valid_before is next year
    #   a TLS SERVER certificate from the same CA: ca=False, EKU=serverAuth, KeyUsage with
    #     no digitalSignature
    #
    # The third is the one that matters. Registering a general-purpose CA as an issuer trust
    # anchor silently promoted EVERY end-entity certificate that CA had ever issued to
    # identity-credential issuer. This package's own cli.py already documents walt.id
    # refusing a leaf for a missing digitalSignature KeyUsage, so the field was known about
    # and simply not read here.
    # At the instant the verdict is reached for: `verify_presentation(now=)` governed the key
    # binding's iat and the credential's exp and nbf, and this window alone read the wall clock,
    # so a leaf that had expired by `now` still chained (2026-10-01).
    now = _utcnow() if now is None else datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    why = _outside_validity(leaf, now, "the x5c leaf")
    if why:
        return why
    for below, ca in enumerate(intermediates):
        why = _outside_validity(ca, now, "x5c certificate %d" % (below + 1))
        if why:
            return why
        if not _may_certify(ca, below):
            return None
    if intermediates:
        # The anchor's own pathLenConstraint, when it states one, bounds the CAs sent beneath it.
        try:
            limit = anchor.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
        except x509.ExtensionNotFound:
            limit = None
        except Exception:  # noqa: BLE001  a malformed constraint is not a usable permission
            return None
        if limit is not None and len(intermediates) > limit:
            return None

    # digitalSignature, when the certificate states a KeyUsage at all. A certificate that
    # says what it may be used for and does not say "sign" is not a signing certificate.
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return ""
    except Exception:  # noqa: BLE001  a malformed extension is not a usable permission
        return "the x5c leaf's key usage does not parse, so it permits no credential signing"
    if not usage.digital_signature:
        return ("the x5c leaf's key usage does not include digitalSignature, so it permits no "
                "credential signing")
    # The leaf's extended key usage is `_leaf_eku_refusal`'s, read once a chain is found, so that
    # its refusal says what it is.
    return ""


def _leaf_eku_refusal(leaf):
    """"" when the x5c leaf's extended key usage admits an issuer's signature, else why not.

    An extended key usage that names purposes without naming this one is a certificate for
    something else; serverAuth alone is the TLS certificate case in `_chains_to`. A leaf that
    states none is not restricted by one. Until 2026-10-10 this was the last step of `_chains_to`,
    and its refusal read "does not chain to any configured trust anchor".
    """
    try:
        oids = list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        return ""
    except Exception:  # noqa: BLE001  a malformed extension is not a usable permission
        return ("the x5c leaf's extended key usage does not parse, so it permits no credential "
                "signing")
    if x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in oids or set(oids) & _ISSUER_EKUS:
        return ""
    return ("the x5c leaf's extended key usage permits no credential signing: %s"
            % (", ".join(oid.dotted_string for oid in oids) or "it names no purpose"))


def _leaf_names(leaf, iss):
    """"" when the x5c `leaf` gives `iss` as one of its own names, None when it gives no name an
    `iss` could be, else why the credential is refused.

    With `x5c`, the issuer of an SD-JWT VC IS the subject of the end-entity certificate (SD-JWT
    VC draft 19, section 2.5) and `iss` is optional. Until 2026-09-28 an `iss` was never
    compared with anything: issuer A's leaf signed a credential naming issuer B, it verified as
    B's, `claims["iss"]` said B, and a status resolver given that `iss` read B's list, VALID at
    an index B had issued (measured, this tree and 1.0.0rc7 alike).

    A URI subjectAltName is a name and is matched exactly. A leaf that names only DNS hosts
    binds an https `iss` on one of them. URI names come first: a Polaris wallet-copy leaf
    names its issuer URL and also the host every agency on it shares, and the host must not
    make one agency's key name another agency's URL.

    DNS names are compared as ASCII only. A DNS name is an IA5String, and an internationalized
    one is written as an A-label; str.lower() folds U+212A (the Kelvin sign) into "k", so before
    2026-10-14 a leaf naming "\u212aent.edu" bound https://kent.edu and an ASCII leaf bound an
    iss written with the Kelvin sign. A leaf with a non-ASCII DNS name is refused, as one whose
    subjectAltName does not parse is: no CA may issue it, and it is not taken to name nobody. An
    https `iss` binds on a DNS host only when it is ASCII.

    A leaf that names neither leaves `iss` unbound (None). Until 2026-10-10 it could carry no
    `iss` at all, and the EU reference PID issuer's document-signer certificates have no
    subjectAltName while its PIDs carry `iss` (oauth-sd-jwt-vc issue #433). The issuer is then the
    leaf, its subject under the anchor it chained to, and the verdict reports `iss` as unbound:
    out of `claims` and away from the status resolver, so B's name in A's credential still reaches
    nothing keyed by issuer. A leaf that names an issuer still has to name this one; a name that
    disagrees is the case above, not an absence.
    """
    if not isinstance(iss, str) or not iss:
        return "the credential's iss is %r, which is not an issuer identifier" % (iss,)
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = names.get_values_for_type(x509.UniformResourceIdentifier)
        hosts = names.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        uris, hosts = [], []
    except Exception:  # noqa: BLE001  a malformed extension names nobody
        return "the issuer certificate's subjectAltName does not parse, so it names no issuer"
    if not all(h.isascii() for h in hosts):
        return ("the issuer certificate names a DNS host that is not ASCII (%s), which no CA may "
                "issue: a DNS name is an IA5String" % ", ".join(repr(h) for h in hosts if not h.isascii()))
    hosts = [h.lower() for h in hosts]
    if uris:
        if iss in uris:
            return ""
        return ("the credential names issuer %r and the certificate that signed it names %s"
                % (iss, ", ".join(repr(u) for u in uris)))
    if hosts:
        try:
            url = urllib.parse.urlsplit(iss)
            bound = (iss.isascii() and url.scheme == "https" and url.username is None
                     and url.password is None and url.hostname in hosts)
        except ValueError:
            bound = False
        if bound:
            return ""
        return ("the credential names issuer %r and the certificate that signed it names only "
                "the host(s) %s" % (iss, ", ".join(repr(h) for h in hosts)))
    return None


def _subject_of(cert):
    """A certificate's subject as an RFC 4514 string, or None when it does not read as one. For
    the verdict's issuer fields, which must not turn a verdict into an exception."""
    try:
        return cert.subject.rfc4514_string()
    except Exception:  # noqa: BLE001  an unreadable subject names nobody
        return None


# ------------------------------------------------------------------------- disclosures

def _committed_digests(payload, by_digest):
    """Every digest the issuer committed to, following recursive disclosures to a fixpoint.

    draft-ietf-oauth-selective-disclosure-jwt section 4.2.4.1: a disclosure's VALUE may
    itself carry `_sd`, so the issuer commits to the outer digest only and the inner one is
    reachable solely through the outer disclosure. Walking the signed payload alone missed
    those, and a conformant credential was refused with "a disclosure was presented that the
    issuer never committed to". The EUDI PID uses exactly this shape for `address`.

    The workaround people reach for is to also list the inner digest at top level, and it
    leaks: the nested claim then resolves as a TOP-LEVEL claim as well, which is the opposite
    of selective disclosure. Measured both ways 2026-09-17.

    A fixpoint, not recursion into unverified data: a digest is only followed once it is
    already committed, so a disclosure the issuer never vouched for can never widen the set.
    """
    out = set()
    _collect_digests(payload, out)
    for _ in range(MAX_RESOLVE_DEPTH):
        grown = set(out)
        for digest in out:
            disclosure = by_digest.get(digest)
            if not disclosure:
                continue
            # [salt, name, value] commits through its value; [salt, value] likewise.
            _collect_digests(disclosure[-1], grown)
        if grown == out:
            break
        out = grown
    return out


def _collect_digests(node, out):
    """Every digest this node commits to directly, wherever it appears."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "_sd" and isinstance(value, list):
                out.update(d for d in value if isinstance(d, str))
            else:
                _collect_digests(value, out)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict) and set(item) == {"..."} and isinstance(item["..."], str):
                out.add(item["..."])
            else:
                _collect_digests(item, out)


def _repeated_digest(payload, by_digest):
    """A digest the issuer-signed payload commits to more than once, directly or through the
    value of a disclosure it commits to, else None.

    RFC 9901 section 7.1: "If any digest value is encountered more than once in the
    Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT
    MUST be rejected." `_resolve` memoizes a repeated digest so that it cannot blow up, and
    until 2026-10-01 that was all that happened to one: a disclosure stood in two places in
    the claims, and a repeated digest among the undisclosed ones passed unremarked.

    Each disclosure is followed at most once, because its digest's second appearance ends the
    walk, so the work is bounded by the size of what was presented.
    """
    seen = set()
    stack = [payload]
    while stack:
        node = stack.pop()
        found = []
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "_sd" and isinstance(value, list):
                    found.extend(d for d in value if isinstance(d, str))
                else:
                    stack.append(value)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict) and set(item) == {"..."} and isinstance(item["..."], str):
                    found.append(item["..."])
                else:
                    stack.append(item)
        for digest in found:
            if digest in seen:
                return digest
            seen.add(digest)
            disclosure = by_digest.get(digest)
            if disclosure:
                stack.append(disclosure[-1])
    return None


class _TooDeep(ValueError):
    """The resolver hit its depth cap. A ValueError so existing handlers see it."""


def _resolve(node, by_digest, used, collisions=None, depth=0, memo=None, path=(),
             disclosed=None):
    """Rebuild the claims by substituting disclosed values for the digests standing in.

    `disclosed`, when given a set, collects the path of every claim a disclosure supplied
    (`path` is where `node` sits). A repeated digest is refused before this runs, so each
    disclosure has one path and the memo below never hides a second one.

    `collisions` collects any disclosure whose name is already present at the same level.
    draft-ietf-oauth-selective-disclosure-jwt section 9.3 requires the verifier to REJECT
    that, and until 2026-09-17 this function silently overwrote instead. Measured: a
    disclosure named `iss` replaced the real issuer in the returned claims while the verdict
    stayed authentic, and one named `cnf` returned a key that was NOT the key the key
    binding had been checked against. The clear-text claims are written first and the
    disclosed ones second, so the disclosure always won.
    """
    if depth > MAX_RESOLVE_DEPTH:
        raise _TooDeep("the credential nests disclosures deeper than %d levels"
                       % MAX_RESOLVE_DEPTH)
    # The memo is what makes this linear. A depth cap alone does not help: the blowup is
    # WIDTH, not depth. A disclosure whose value lists the same digest twice doubles the work
    # at every level, so thirty nested disclosures in about 6 KB cost 2**30 node visits and
    # depth 24 was measured not finishing in twenty seconds. Resolving each digest once and
    # reusing the result makes the same credential cost thirty.
    if memo is None:
        memo = {}
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key in ("_sd", "_sd_alg"):
                continue
            out[key] = _resolve(value, by_digest, used, collisions, depth + 1, memo,
                                path + (key,), disclosed)
        sd = node.get("_sd")
        # `node.get("_sd", []) or []` let a non-list through: `_sd: 5` reached the for-loop
        # and raised TypeError out of the verifier. The digests themselves must be strings
        # for the same reason one level down.
        for digest in (sd if isinstance(sd, list) else []):
            if not isinstance(digest, str):
                continue
            disclosure = by_digest.get(digest)
            if disclosure and len(disclosure) == 3:
                used.add(digest)
                name = disclosure[1]
                if name in out and collisions is not None:
                    collisions.append(name)
                if disclosed is not None:
                    disclosed.add(path + (name,))
                if digest not in memo:
                    memo[digest] = _resolve(disclosure[2], by_digest, used, collisions,
                                            depth + 1, memo, path + (name,), disclosed)
                out[name] = memo[digest]
        return out
    if isinstance(node, list):
        out = []
        for item in node:
            if isinstance(item, dict) and set(item) == {"..."}:
                disclosure = by_digest.get(item["..."]) if isinstance(item["..."], str) else None
                if disclosure and len(disclosure) == 2:
                    key = item["..."]
                    used.add(key)
                    if disclosed is not None:
                        disclosed.add(path + (len(out),))
                    if key not in memo:
                        memo[key] = _resolve(disclosure[1], by_digest, used, collisions,
                                             depth + 1, memo, path + (len(out),), disclosed)
                    out.append(memo[key])
                continue
            out.append(_resolve(item, by_digest, used, collisions, depth + 1, memo,
                                path + (len(out),), disclosed))
        return out
    return node


# -------------------------------------------------------------------- transaction data

#: The hash functions `transaction_data_hashes` may be computed with, by their names in the IANA
#: "Named Information Hash Algorithm" registry. OpenID4VP 1.0 Appendix B.3.3.1: "If this
#: parameter is not present, a default value of sha-256 MUST be used. To promote
#: interoperability, implementations MUST support the sha-256 hash algorithm."
TRANSACTION_DATA_HASH_ALGS = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384,
                              "sha-512": hashlib.sha512}
DEFAULT_TRANSACTION_DATA_HASH_ALG = "sha-256"

#: The transaction data types of EU TS12 ("Specification of Strong Customer Authentication (SCA)
#: Implementation with the Wallet", v1.0.1) all live under this prefix: urn:eudi:sca:payment:1,
#: login_risk_transaction:1, account_access:1 and emandate:1. A key binding JWT that binds one
#: for the credential it names carries TS12 section 3.6's three claims as well.
TS12_TYPE_PREFIX = "urn:eudi:sca:"

#: TS12 section 3.6, `amr`: "at least two different objects representing authentication
#: categories. Each object consists of a key representing the category and a value specifying
#: the method used." The categories and methods the specification defines:
TS12_AMR = {
    "knowledge": frozenset(("pin_less_than_6_digits", "pin_6_or_more_digits",
                            "passphrase_less_than_8_chars", "passphrase_8_to_11_chars",
                            "passphrase_12_or_more_chars", "pattern", "other")),
    "possession": frozenset(("key_in_remote_wscd", "key_in_local_external_wscd",
                             "key_in_local_internal_wscd", "key_in_local_native_wscd", "other")),
    "inherence": frozenset(("fingerprint_device", "fingerprint_external", "face_device",
                            "face_external", "other")),
}

# WHICH ENTRIES A KEY BINDING JWT BINDS, when a response presents more than one credential. SIROS
# calls it B8 (sirosfoundation/wallet-frontend #354, #361) and openid/OpenID4VP #754 asks it too.
# With one credential there is no question: every entry names it. With several, the text is:
#
#   5.1      credential_ids: "Non-empty array of strings each referencing a Credential requested
#            by the Verifier that can be used to authorize this transaction. [...] If there is
#            more than one element in the array, the Wallet MUST use only one of the referenced
#            Credentials for transaction authorization."
#   8.4      "The Wallet that received the transaction_data parameter in the request MUST include
#            a representation or reference to the data in the respective Credential presentation.
#            How this is done is transaction data type specific."
#   B.3.3.1  transaction_data_hashes: "Each of these hashes is calculated using a hash function
#            over the string received in the transaction_data request parameter (base64url
#            decoding is not performed before hashing). Each hash value ensures the integrity of,
#            and maps to, the respective transaction data object."
#
# "The respective Credential presentation" reads as the presentation of a credential the entry
# names, which is the per-credential reading; no sentence says the presentation of a credential
# the entry does NOT name must leave it out, which is the room the all-entries reading stands in;
# and 8.4 hands the rest to the transaction data type, where TS12 says nothing. So this verifier
# implements both and the caller names one; nothing is accepted under a reading nobody chose:
#
#   per_credential  SIROS's (#354: "the entries whose credential_ids include that credential's
#                   query id"): a key binding JWT carries the entries that name its credential, in
#                   request order. An entry naming two or more PRESENTED credentials is bound by
#                   exactly one of them, the wallet's choice, because 5.1 decides that case: "If
#                   there is more than one element in the array, the Wallet MUST use only one of
#                   the referenced Credentials for transaction authorization." Read literally,
#                   SIROS's rule would put it in both; a response that binds it twice, or not at
#                   all, is refused (verify_response).
#   all_entries     SUNET/vc's (pkg/openid4vp/validator.go validateTransactionData at 0e637904,
#                   which requires len(transaction_data_hashes) == len(TransactionData)): every key
#                   binding JWT carries every entry, in request order.
#
# Elsewhere: multipaz files each entry under every query id it names and requires the exact count
# in each key binding JWT, zipped in order (openwallet-foundation/multipaz cd9578b3,
# sdjwt/SdJwtKb.kt L122, L136; verification/VerificationUtil.kt L892): per_credential, as here.
# The EU reference verifier filters per query id too, then accepts any non-empty subset in any
# order (eudi-srv-verifier-endpoint df07af2f, port/input/PostWalletResponse.kt L166,
# ValidateSdJwtVcOrMsoMdocVerifiablePresentation.kt L274-276). Here every expected entry is
# required, in the request's order: a subset leaves a transaction the verifier sent unbound,
# where 8.4 says the wallet MUST include it.
PER_CREDENTIAL = "per_credential"
ALL_ENTRIES = "all_entries"
TRANSACTION_DATA_SCOPES = (PER_CREDENTIAL, ALL_ENTRIES)


def transaction_data_hash(raw, alg=DEFAULT_TRANSACTION_DATA_HASH_ALG):
    """base64url(HASH(the ASCII bytes of one transaction_data entry as the request sent it)).

    The STRING, never the JSON it decodes to (OpenID4VP 1.0 B.3.3.1, quoted above): two encodings
    of one object are two transactions, and a wallet that hashes the decoded bytes, or a
    re-serialisation of them, binds something the verifier never sent. SUNET/vc's
    HashTransactionData (pkg/openid4vp/request_object.go) hashes the string the same way.
    """
    return b64u_encode(TRANSACTION_DATA_HASH_ALGS[alg](raw.encode("ascii")).digest())


class TransactionDataEntry:
    """One entry of a request's `transaction_data` (OpenID4VP 1.0 section 5.1), as sent and as read.

    `raw` is the base64url string exactly as the request carries it, and it is the only thing
    hashed. The rest is what it decodes to: `type`, `credential_ids` (the DCQL credential query ids
    that may authorize it), `hashes_alg` (the algorithms it allows, or None for the sha-256
    default) and the decoded object, `document`. Raises ValueError on an entry that is not one:
    not canonical base64url, not a JSON object (one naming a member twice included), or without
    a non-empty string `type` and a non-empty array of non-empty string `credential_ids`.

    A `transaction_data_hashes_alg` that is a bare string is read as a list of one, as wallets
    tolerate it (SIROS's vector `hash_alg_string`); B.3.3.1 makes it an array, and a request this
    package builds is held to that (verifier.transaction_data_entries).
    """

    __slots__ = ("raw", "type", "credential_ids", "hashes_alg", "document")

    def __init__(self, raw):
        if not isinstance(raw, str) or not raw:
            raise ValueError("a transaction_data entry is a non-empty base64url string")
        try:
            document = _json_bounded(b64u_decode(raw), "transaction_data entry", unique_keys=True)
        except ValueError as exc:  # binascii, Unicode and JSON errors are all ValueErrors
            raise ValueError("a transaction_data entry does not decode to JSON: %s" % exc) from None
        if not isinstance(document, dict):
            raise ValueError("a transaction_data entry decodes to a JSON %s, not an object"
                             % type(document).__name__)
        kind, ids = document.get("type"), document.get("credential_ids")
        if not isinstance(kind, str) or not kind:
            raise ValueError("a transaction_data entry's type must be a non-empty string")
        if (not isinstance(ids, list) or not ids
                or not all(isinstance(i, str) and i for i in ids)):
            raise ValueError("a transaction_data entry's credential_ids must be a non-empty array "
                             "of non-empty strings")
        algs = document.get("transaction_data_hashes_alg")
        if isinstance(algs, str):
            algs = [algs]
        if algs is not None and (not isinstance(algs, list) or not algs
                                 or not all(isinstance(a, str) and a for a in algs)):
            raise ValueError("a transaction_data entry's transaction_data_hashes_alg must be a "
                             "non-empty array of algorithm names")
        self.raw = raw
        self.type = kind
        self.credential_ids = tuple(ids)
        self.hashes_alg = None if algs is None else tuple(algs)
        self.document = document

    @property
    def is_ts12(self):
        return self.type.startswith(TS12_TYPE_PREFIX)

    def allowed_algs(self):
        """The algorithms a key binding JWT may hash this entry with (B.3.3.1)."""
        return set(self.hashes_alg or (DEFAULT_TRANSACTION_DATA_HASH_ALG,))


class TransactionDataBinding:
    """What ONE key binding JWT must carry for a request's transaction_data.

    `entries` are the request's entries (TransactionDataEntry), in the request's order;
    `query_id` is the DCQL credential query the presentation answers; `scope` is PER_CREDENTIAL
    or ALL_ENTRIES (above); `response_mode` is the request's; `jti_fresh` is called with a
    TS12 `jti` and says whether it is new, recording it (a JtiMemory); `presented` is the query
    ids of every credential the response presents, this one alone by default.

    `expected` is the positions of the entries this key binding JWT must hash, in order.
    `optional`, under PER_CREDENTIAL only, is the positions of entries naming this credential and
    another presented one: OpenID4VP 1.0 section 5.1, "If there is more than one element in the
    array, the Wallet MUST use only one of the referenced Credentials for transaction
    authorization." This JWT may bind such an entry or leave it to the other; that exactly one
    of them binds it is a property of the response, and verify_response holds it there.
    `ts12` says whether TS12's claims are due whatever optional entries it binds: they are when
    a TS12 entry it must bind names this credential, the one TS12 calls the SCA attestation.
    """

    __slots__ = ("entries", "query_id", "scope", "expected", "optional", "readings_agree", "ts12",
                 "response_mode", "jti_fresh")

    def __init__(self, entries, query_id, *, scope, response_mode, jti_fresh, presented=None):
        if scope not in TRANSACTION_DATA_SCOPES:
            raise ValueError("the transaction_data scope is %r; it is one of %s"
                             % (scope, ", ".join(TRANSACTION_DATA_SCOPES)))
        self.entries = tuple(entries)
        self.query_id = query_id
        self.scope = scope
        presented = {query_id} | set(presented or ())
        candidates = [set(e.credential_ids) & presented for e in self.entries]
        named = tuple(i for i, c in enumerate(candidates) if query_id in c)
        alone = tuple(i for i in named if candidates[i] == {query_id})
        every = tuple(range(len(self.entries)))
        if scope == ALL_ENTRIES:
            self.expected, self.optional = every, ()
        else:
            self.expected = alone
            self.optional = tuple(i for i in named if i not in alone)
        self.readings_agree = alone == every
        self.ts12 = any(self.entries[i].is_ts12 for i in (named if scope == ALL_ENTRIES
                                                          else self.expected))
        self.response_mode = response_mode
        self.jti_fresh = jti_fresh

    def report(self, alg=None, jti=None, bound=None, ts12=None):
        return {"credential": self.query_id, "scope": self.scope, "expected": list(self.expected),
                "optional": list(self.optional),
                "bound": list(self.expected if bound is None else bound),
                "readings_agree": self.readings_agree, "alg": alg,
                "ts12": self.ts12 if ts12 is None else ts12, "jti": jti}

    def describe(self, positions=None):
        positions = self.expected if positions is None else positions
        return ("entries %s of the request's %d (%s)"
                % (", ".join(str(i) for i in positions) or "none", len(self.entries), self.scope))


class JtiMemory:
    """The `jti` values already used, for TS12 section 3.6: "A fresh, cryptographically random
    value [...] This value SHALL be unique for each presentation."

    Called with a jti, it records it and answers True when it had not been seen. Thread-safe.
    `retention_seconds` bounds how long one is remembered (None: for the object's life), so a
    verifier holds a jti for that long and no longer: it is not a register of every jti ever
    used, and a deployment that needs one checks `verdict.transaction_data["jti"]` in its own.
    """

    def __init__(self, retention_seconds=None):
        self.retention_seconds = retention_seconds
        self._seen = {}
        self._lock = threading.Lock()

    def __call__(self, jti):
        now = time.time()
        with self._lock:
            if self.retention_seconds is not None:
                cutoff = now - self.retention_seconds
                for old in [j for j, at in self._seen.items() if at < cutoff]:
                    del self._seen[old]
            if jti in self._seen:
                return False
            self._seen[jti] = now
            return True


def _check_transaction_data(kb_payload, binding):
    """The key binding JWT against `binding`: a refusal Verdict, or the report of what it bound.

    Order: whether the hashes are there at all, the algorithm they were made with, which optional
    entries it took, then each hash in turn, then TS12's claims. The jti is recorded last, so only
    a key binding JWT that passed every other check of verify_presentation uses one up; a Verifier
    that then refuses the presentation for its claims or its status has still seen that jti.
    """
    present = "transaction_data_hashes" in kb_payload
    hashes = kb_payload.get("transaction_data_hashes")
    if not binding.expected and not binding.optional:
        if present:
            return _refuse("transaction_data_extra",
                           "the key binding JWT carries transaction_data_hashes and the request "
                           "asked this credential (%r) to bind no entry under the %s reading"
                           % (binding.query_id, binding.scope))
        return binding.report()
    if not present:
        if binding.expected:
            return _refuse("transaction_data_missing",
                           "the key binding JWT carries no transaction_data_hashes, and the request "
                           "asked it to bind %s" % binding.describe())
        # Only entries another presented credential may bind instead, and it bound none of them.
        return binding.report(bound=())
    if not isinstance(hashes, list) or not all(isinstance(h, str) for h in hashes):
        return _refuse("transaction_data_mismatch",
                       "the key binding JWT's transaction_data_hashes is not an array of strings")

    # B.3.3.1: the algorithm "MUST be one of" the values the request allowed, sha-256 when it named
    # none, and the claim is "REQUIRED when this parameter was present in the transaction_data
    # request parameter". Every entry this one JWT binds must allow the one it used.
    alg = kb_payload.get("transaction_data_hashes_alg")
    if "transaction_data_hashes_alg" in kb_payload:
        if not isinstance(alg, str):
            return _refuse("transaction_data_alg",
                           "the key binding JWT's transaction_data_hashes_alg is a JSON %s, not "
                           "the string naming the one algorithm its hashes were made with"
                           % type(alg).__name__)
        if alg not in TRANSACTION_DATA_HASH_ALGS:
            offered = set().union(*(binding.entries[i].allowed_algs()
                                    for i in binding.expected + binding.optional))
            if alg not in offered:
                return _refuse("transaction_data_alg",
                               "the key binding JWT hashed with %r, which is not an algorithm every "
                               "entry it binds allows (%s)" % (alg, ", ".join(sorted(offered))))
            return _refuse("transaction_data_alg",
                           "the key binding JWT hashed with %r, which the request allowed and this "
                           "verifier cannot compute (%s)"
                           % (alg, ", ".join(sorted(TRANSACTION_DATA_HASH_ALGS))))
    used = DEFAULT_TRANSACTION_DATA_HASH_ALG if alg is None else alg
    # The optional entries it took (5.1, one presented credential of several binds each), then
    # everything it binds, in the request's order.
    taken = tuple(i for i in binding.optional
                  if transaction_data_hash(binding.entries[i].raw, used) in hashes)
    bound = tuple(sorted(binding.expected + taken))
    if not bound:
        return _refuse("transaction_data_extra",
                       "the key binding JWT carries transaction_data_hashes and binds none of the "
                       "entries it may bind (%s)" % binding.describe(binding.optional))
    covered = [binding.entries[i] for i in bound]
    allowed = set.intersection(*(e.allowed_algs() for e in covered))
    if alg is not None and alg not in allowed:
        return _refuse("transaction_data_alg",
                       "the key binding JWT hashed with %r, which is not an algorithm every "
                       "entry it binds allows (%s)" % (alg, ", ".join(sorted(allowed)) or "none"))
    if alg is None and any(e.hashes_alg is not None for e in covered):
        return _refuse("transaction_data_alg",
                       "the key binding JWT names no transaction_data_hashes_alg, which B.3.3.1 "
                       "requires when the request named algorithms (%s)"
                       % (", ".join(sorted(allowed)) or "none",))

    wanted = [transaction_data_hash(e.raw, used) for e in covered]
    if len(hashes) < len(wanted):
        return _refuse("transaction_data_missing",
                       "the key binding JWT carries %d transaction_data_hashes and the request "
                       "asked it to bind %s" % (len(hashes), binding.describe(bound)))
    if len(hashes) > len(wanted):
        return _refuse("transaction_data_extra",
                       "the key binding JWT carries %d transaction_data_hashes and the request "
                       "asked it to bind %s" % (len(hashes), binding.describe(bound)))
    for position, (got, want) in enumerate(zip(hashes, wanted)):
        if got != want:
            entry = covered[position]
            decoded = b64u_encode(TRANSACTION_DATA_HASH_ALGS[used](b64u_decode(entry.raw)).digest())
            why = (": it is the hash of the decoded JSON, and B.3.3.1 hashes the string as sent"
                   if got == decoded else
                   ": it is another entry's, so the order is not the request's" if got in wanted
                   else "")
            return _refuse("transaction_data_mismatch",
                           "transaction_data_hashes[%d] is not the %s hash of entry %d as the "
                           "request sent it%s" % (position, used, bound[position], why))

    jti = None
    ts12 = binding.ts12 or any(binding.entries[i].is_ts12 for i in taken)
    if ts12:
        # TS12 section 3.6, for the presentation of the credential a TS12 entry names: "jti:
        # REQUIRED", "response_mode: REQUIRED The value of the response_mode parameter given in
        # the [OID4VP] Authorization Request", "amr: REQUIRED".
        jti = kb_payload.get("jti")
        if not isinstance(jti, str) or not jti:
            return _refuse("ts12_jti",
                           "the key binding JWT binds a TS12 transaction and carries no jti "
                           "(TS12 3.6 requires one, unique to the presentation)")
        if kb_payload.get("response_mode") != binding.response_mode:
            return _refuse("ts12_response_mode",
                           "the key binding JWT's response_mode is %r and the request's was %r "
                           "(TS12 3.6)" % (kb_payload.get("response_mode"), binding.response_mode))
        amr = kb_payload.get("amr")
        if not isinstance(amr, list) or not all(
                isinstance(m, dict) and len(m) == 1 and isinstance(next(iter(m.values())), str)
                for m in amr):
            return _refuse("ts12_amr",
                           "the key binding JWT's amr is not an array of single-member objects, "
                           "each naming one authentication method (TS12 3.6)")
        categories = sorted({k for m in amr for k, v in m.items() if v in TS12_AMR.get(k, ())})
        if len(categories) < 2:
            return _refuse("ts12_amr",
                           "the key binding JWT's amr names %d of TS12's authentication "
                           "categories (%s); TS12 3.6 requires at least two"
                           % (len(categories), ", ".join(categories) or "none"))
        if not binding.jti_fresh(jti):
            return _refuse("ts12_jti",
                           "the key binding JWT's jti has been used before; TS12 3.6 makes it "
                           "unique to each presentation")
    return binding.report(alg=used, jti=jti, bound=bound, ts12=ts12)


# ------------------------------------------------------------------------ the verifier

def verify_presentation(presentation, *, expected_nonce, expected_audience,
                        issuer_jwks=None, trust_anchors=None, now=None,
                        max_skew_seconds=DEFAULT_MAX_SKEW_SECONDS,
                        require_key_binding=True, expected_vct=None,
                        status_resolver=None, transaction_data=None):
    """Verify one SD-JWT VC presentation. Returns a Verdict and never raises on bad input.

    `presentation` is the `~`-separated string a wallet sent. `expected_nonce` and
    `expected_audience` are what the authorization request asked for: passing anything else,
    or passing what the presentation itself claims, turns two of the conformance suite's
    negative tests into passes and makes every presentation replayable.

    `expected_vct` is the credential TYPE the query asked for, as a string or a collection of
    them. `Verifier` builds a DCQL query carrying `vct_values` and, until 2026-09-17, never
    passed it here and this function never read `vct`: a verifier that asked for a personal
    identification credential accepted any credential the same issuer signed, and returned
    `given_name` off a loyalty card as though it came from a PID. Left None it is not
    checked, which is what a caller doing its own type selection wants.

    `transaction_data` is a TransactionDataBinding when the request carried `transaction_data`
    (OpenID4VP 1.0 section 8.4), and then the key binding JWT is held to it once every other
    check has passed: the hashes of exactly the entries it must bind, over each string as sent,
    in the request's order, made with an algorithm the request allowed; and, for a TS12 entry
    naming this credential, a fresh `jti`, the request's `response_mode` and two `amr`
    categories. None, the default, looks at none of those claims: a request without
    transaction_data is verified exactly as it was before this parameter existed.
    """
    if not _HAVE_CRYPTO:
        return _refuse("no_backend", "the cryptography package is not installed, so no "
                                     "signature can be checked. Install polaris-oid4vp with "
                                     "its dependencies rather than reading this as a refusal "
                                     "of the credential")
    if not isinstance(presentation, str) or not presentation.strip():
        return _refuse("malformed", "the presentation is empty")
    if len(presentation) > MAX_PRESENTATION_BYTES:
        # Before any parsing. There was no bound at all until 2026-09-17, and a 117 MiB
        # presentation was measured verifying as authentic in 1.46 s having built a
        # two-million-element set on the way.
        return _refuse("malformed", "the presentation is %d bytes, over the %d byte limit"
                                    % (len(presentation), MAX_PRESENTATION_BYTES))
    if not expected_nonce or not expected_audience:
        return _refuse("misconfigured", "a nonce and an audience must be supplied by the "
                                        "caller: without them the two checks that stop "
                                        "replay are not being made")
    now = time.time() if now is None else now

    parts = presentation.split("~")
    issuer_jwt, rest = parts[0], parts[1:]
    kb_jwt = rest.pop() if rest else ""
    disclosures_b64 = [d for d in rest if d]

    # 1. the issuer-signed JWT
    try:
        header, payload, signing_input, signature = _parse_jws(issuer_jwt)
    except (ValueError, json.JSONDecodeError) as exc:
        return _refuse("malformed", "the issuer-signed JWT does not parse: %s" % exc)
    if header.get("typ") != ISSUER_TYP:
        why = (": `vc+sd-jwt` is a W3C VC Data Model credential, whose `validUntil` and "
               "`credentialStatus` this verifier does not read"
               if header.get("typ") == "vc+sd-jwt" else "")
        return _refuse("issuer_typ", "the issuer JWT declares typ=%r, and this verifier only "
                                     "checks %r%s" % (header.get("typ"), ISSUER_TYP, why))
    if header.get("alg") not in ACCEPTED_ALGS:
        return _refuse("issuer_alg", "the issuer JWT declares alg=%r, which is not in the "
                                     "accepted set %r" % (header.get("alg"), ACCEPTED_ALGS))
    keys, why, certified = _issuer_public_keys(header, issuer_jwks, trust_anchors, now)
    if not keys:
        return _refuse("issuer_key", why)
    if not any(_verify_es256(key, signing_input, signature) for key in keys):
        return _refuse("issuer_signature", "the issuer signature over the credential does "
                                           "not verify under any trusted issuer key")
    leaf, anchor = certified or (None, None)
    iss_bound = None
    if leaf is not None and "iss" in payload:
        why = _leaf_names(leaf, payload["iss"])
        if why:
            return _refuse("issuer_key", why)
        iss_bound = why == ""            # None: the leaf names no issuer, so nothing binds iss
    # Who signed, for the verdict. An `iss` nothing binds is left out of `claims` and away from
    # the status resolver: it is the credential's word about itself, and every decision keyed by
    # issuer would otherwise take it as the issuer's name (2026-10-10).
    signer = {} if leaf is None else {
        "issuer_subject": _subject_of(leaf), "issuer_anchor": _subject_of(anchor),
        "iss_bound": iss_bound, "unbound_iss": payload["iss"] if iss_bound is False else None}
    issuer = None if iss_bound is False else payload.get("iss")
    # RFC 7515 4.1.11: a JWS whose `crit` names an extension the recipient does not
    # implement is invalid, and this verifier implements none. The response JWE was held to
    # that in 1.0.0rc12; the credential and its key binding JWT were not, so an extension
    # the issuer marked as binding was ignored and the credential verified.
    if "crit" in header:
        return _refuse("crit", "the issuer JWT's crit names %r, and this verifier implements "
                               "no JWS extension (RFC 7515 4.1.11)" % (header.get("crit"),))

    if expected_vct is not None:
        wanted = ({expected_vct} if isinstance(expected_vct, str)
                  else {v for v in expected_vct if isinstance(v, str)})
        # A string first: `vct` in a set is a hash lookup, and an issuer-signed array or
        # object raised TypeError there (2026-09-28).
        vct = payload.get("vct")
        if not isinstance(vct, str) or vct not in wanted:
            return _refuse("vct", "the credential is of type %r and this request asked for "
                                  "%s: a credential of the wrong type is not an answer to "
                                  "the question that was put" % (vct, sorted(wanted)))

    if payload.get("_sd_alg", "sha-256") != "sha-256":
        return _refuse("sd_alg", "the credential declares _sd_alg=%r; this verifier computes "
                                 "sha-256 and will not pretend to have checked another"
                                 % payload.get("_sd_alg"))

    # 1b. WHETHER THE CREDENTIAL IS STILL VALID AT ALL. Neither `exp` nor `nbf` appeared
    # anywhere in this file until 2026-09-17: a credential its own issuer stamped as expired
    # ten years ago verified as authentic, and so did one not valid until 2527. For an
    # offline SD-JWT VC these two claims are the ONLY expiry mechanism there is; the status
    # list is a separate, online question. Refusing a malformed value rather than ignoring it
    # is deliberate: a credential that declares `exp: "soon"` or `exp: NaN` has said
    # something about its own lifetime that this verifier cannot evaluate, and treating that
    # as "no expiry" is how NaN defeated the key-binding window one field over.
    for claim, human in (("exp", "expired"), ("nbf", "not yet valid")):
        if claim not in payload:
            continue
        value = payload[claim]
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value)):
            return _refuse("credential_validity",
                           "the credential's %s is %r, which is not a finite number: its "
                           "lifetime cannot be evaluated and will not be assumed" % (claim, value))
        # The same skew the key binding gets, and for the same reason: clocks differ, and a
        # verifier with none refuses a credential that expired one second ago on a fast clock.
        if claim == "exp" and now > value + max_skew_seconds:
            return _refuse("credential_validity",
                           "the credential %s %.0f seconds ago (exp), outside the %d second "
                           "allowance" % (human, now - value, max_skew_seconds))
        if claim == "nbf" and now < value - max_skew_seconds:
            return _refuse("credential_validity",
                           "the credential is %s for another %.0f seconds (nbf), outside the "
                           "%d second allowance" % (human, value - now, max_skew_seconds))

    # 2. the disclosures, each of which must be one the issuer committed to
    if len(disclosures_b64) > MAX_DISCLOSURES:
        return _refuse("disclosure", "%d disclosures were presented, over the %d limit"
                                     % (len(disclosures_b64), MAX_DISCLOSURES))
    by_digest = {}
    for encoded in disclosures_b64:
        try:
            parsed = _json_bounded(b64u_decode(encoded), "disclosure")
        except (ValueError, json.JSONDecodeError) as exc:
            return _refuse("disclosure", "a disclosure does not decode: %s" % exc)
        if not isinstance(parsed, list) or len(parsed) not in (2, 3):
            return _refuse("disclosure", "a disclosure must be a 2- or 3-element array, got %r"
                                         % (parsed if not isinstance(parsed, list) else len(parsed)))
        digest = _digest(encoded)
        if digest in by_digest:
            return _refuse("disclosure", "the same disclosure was presented twice")
        # A claim name is a JSON object key, so a string. This runs before the commitment
        # check below, on input any holder of one genuine credential writes, and an array or
        # an object reached the reserved-name set lookup and raised TypeError (2026-09-28).
        if len(parsed) == 3 and not isinstance(parsed[1], str):
            return _refuse("disclosure",
                           "a disclosure's claim name is a JSON %s, not a string, so it "
                           "names no claim" % type(parsed[1]).__name__)
        # A 3-element disclosure names a claim, and three names are SD-JWT's own at any depth.
        # The registered claims SD-JWT VC keeps out of disclosures depend on where a disclosure
        # lands, so they are judged once the claims are resolved, below.
        if len(parsed) == 3 and parsed[1] in _RESERVED_DISCLOSURE_NAMES:
            return _refuse("disclosure",
                           "a disclosure is named %r, which SD-JWT reserves for its own "
                           "structure (RFC 9901, sections 4.1.1 and 7.1)" % parsed[1])
        by_digest[digest] = parsed

    # AFTER parsing, not before: a recursive disclosure's inner digest is reachable only
    # through the outer disclosure's decoded value, so the committed set cannot be computed
    # until the disclosures are in hand. The fixpoint only ever follows digests that are
    # ALREADY committed, so a disclosure the issuer never vouched for cannot widen it.
    repeated = _repeated_digest(payload, by_digest)
    if repeated is not None:
        return _refuse("disclosure", "the credential commits to the digest %s... more than once, "
                                     "which RFC 9901 (7.1) requires a verifier to reject"
                                     % repeated[:12])
    committed = _committed_digests(payload, by_digest)
    for digest in by_digest:
        if digest not in committed:
            return _refuse("disclosure", "a disclosure was presented that the issuer never "
                                         "committed to: its digest appears nowhere in the "
                                         "signed payload")

    used = set()
    collisions = []
    disclosed = set()
    try:
        claims = _resolve(payload, by_digest, used, collisions, disclosed=disclosed)
    except _TooDeep as exc:
        return _refuse("disclosure", str(exc))
    # SD-JWT VC draft 19, section 2.2.2.3 (quoted at _NEVER_DISCLOSED), held on the paths the
    # resolver filled: the position judged is the one a relying party reads the claim at, through
    # recursive disclosures and array elements alike, and no second walk of the payload can
    # disagree with the resolver about where a disclosure sits. A repeated digest was refused
    # above, so each disclosure has one path. The shallowest first, so the refusal names a
    # claim before its sub-claims.
    supplied = sorted((p for p in disclosed if p[0] in _NEVER_DISCLOSED),
                      key=lambda p: (len(p), repr(p)))
    if supplied:
        where = (repr(supplied[0][0]) if len(supplied[0]) == 1 else
                 "%s, inside %r" % (json.dumps(list(supplied[0])), supplied[0][0]))
        return _refuse("disclosure",
                       "a disclosure supplies %s, which SD-JWT VC draft 19 (section 2.2.2.3) "
                       "keeps out of disclosures with every claim inside it: the issuer signs it "
                       "in clear text or leaves it out, and a holder-supplied one is not handed "
                       "on" % where)
    if collisions:
        # SD-JWT section 9.3. The clear-text claims go in first and the disclosed ones
        # second, so before this check a disclosure named `iss` simply replaced the issuer in
        # the returned claims and the verdict stayed authentic. `cnf` was the sharpest: the
        # claims named a key that was not the key the key binding was checked against.
        return _refuse("disclosure",
                       "a disclosure is named %r, which the credential already carries in "
                       "clear text. A disclosure that overwrites an existing claim is "
                       "refused rather than applied" % collisions[0])
    if iss_bound is False:
        # `claims["iss"]` is whose credential this is, and an unbound `iss` is not that.
        claims.pop("iss", None)

    # 3. key binding, which is what makes this a presentation rather than a copy
    if not kb_jwt:
        if require_key_binding:
            return _refuse("kb_missing", "the presentation carries no key binding JWT, so "
                                         "nothing ties it to the holder who presented it")
        # The same rule as the key-binding path below. It ran only there, so with key binding
        # not required a disclosure the credential never committed to was accepted (2026-10-01).
        orphans = set(by_digest) - used
        if orphans:
            return _refuse("disclosure", "%d disclosure(s) were presented that resolve to nothing "
                                         "in the credential" % len(orphans))
        # OpenID4VP 1.0 B.3.3: "The transaction data mechanism requires the use of an SD-JWT VC
        # with Cryptographic Holder Binding." With no key binding JWT nothing binds an entry.
        if transaction_data is not None and transaction_data.expected:
            return _refuse("transaction_data_missing",
                           "the presentation carries no key binding JWT, and the request asked it "
                           "to bind %s" % transaction_data.describe())
        return Verdict(True, claims=claims,
                       revocation=_revocation_state(payload, status_resolver, issuer),
                       disclosed=disclosed,
                       transaction_data=None if transaction_data is None else transaction_data.report(),
                       **signer)

    cnf = payload.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        return _refuse("kb_cnf", "the credential carries a key binding JWT but no cnf.jwk to "
                                 "check it against")
    # The holder's key by the same rule as the issuer's (2026-10-01): a key the issuer bound as
    # one for another use does not verify the key binding JWT.
    if _not_an_es256_verification_key(cnf["jwk"]):
        return _refuse("kb_cnf", "the credential's cnf.jwk is not for verifying ES256 signatures; "
                                 "its use, key_ops or alg says otherwise")
    try:
        holder_key = _es256_public_key(cnf["jwk"])
    except ValueError as exc:
        return _refuse("kb_cnf", "the credential's cnf.jwk is not a usable P-256 key: %s" % exc)

    try:
        kb_header, kb_payload, kb_signing_input, kb_signature = _parse_jws(kb_jwt)
    except (ValueError, json.JSONDecodeError) as exc:
        return _refuse("malformed", "the key binding JWT does not parse: %s" % exc)
    if kb_header.get("typ") != KB_TYP:
        return _refuse("kb_typ", "the key binding JWT declares typ=%r rather than %r"
                                 % (kb_header.get("typ"), KB_TYP))
    if kb_header.get("alg") not in ACCEPTED_ALGS:
        return _refuse("kb_alg", "the key binding JWT declares alg=%r, which is not in the "
                                 "accepted set %r" % (kb_header.get("alg"), ACCEPTED_ALGS))
    if "crit" in kb_header:
        return _refuse("crit", "the key binding JWT's crit names %r, and this verifier "
                               "implements no JWS extension (RFC 7515 4.1.11)"
                               % (kb_header.get("crit"),))
    if not _verify_es256(holder_key, kb_signing_input, kb_signature):
        return _refuse("kb_signature", "the key binding JWT signature does not verify under "
                                       "the credential's cnf.jwk, so the holder did not "
                                       "produce this presentation")

    if kb_payload.get("nonce") != expected_nonce:
        return _refuse("nonce", "the key binding JWT's nonce is not the one this request "
                                "asked for, so this presentation was made for somebody else "
                                "or at some other time")
    if kb_payload.get("aud") != expected_audience:
        return _refuse("audience", "the key binding JWT's aud is %r and this verifier is %r: "
                                   "a presentation addressed elsewhere is not ours to accept"
                                   % (kb_payload.get("aud"), expected_audience))
    iat = kb_payload.get("iat")
    # `math.isfinite` is the load-bearing part, and it was missing. Python's json parses the
    # bare literals NaN, Infinity and -Infinity by default, and all three are floats, so they
    # walked past the isinstance test. NaN then defeated the window outright, because every
    # comparison against NaN is False: `abs(now - nan) > 300` is False, so a presentation
    # with `iat: NaN` verified as authentic with the clock set a YEAR ahead. Infinity did the
    # opposite and crashed the refusal itself, on `"%d" % inf`. Both measured 2026-09-17.
    # These are exactly the two conformance modules this file is built around,
    # kb-jwt-iat-in-past and kb-jwt-iat-in-future, defeated by a wallet writing three
    # characters.
    if (not isinstance(iat, (int, float)) or isinstance(iat, bool)
            or not math.isfinite(iat)):
        return _refuse("kb_freshness", "the key binding JWT's iat is %r, which is not a "
                                       "finite number, so its age cannot be established"
                                       % (iat,))
    if abs(now - iat) > max_skew_seconds:
        return _refuse("kb_freshness", "the key binding JWT was minted %.0f seconds from "
                                       "now, outside the %d second window"
                                       % (now - iat, max_skew_seconds))
    # RFC 9901 7.3: the key binding JWT must also be "a valid JWT in all other respects, per
    # RFC 7519", so an `exp` it carries must not have passed and an `nbf` must have. Both were
    # ignored: a holder's proof that declared itself expired an hour ago verified. The same
    # rule, and the same allowance, as the credential's own exp and nbf.
    for claim, human in (("exp", "expired"), ("nbf", "not yet valid")):
        if claim not in kb_payload:
            continue
        value = kb_payload[claim]
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value)):
            return _refuse("kb_freshness", "the key binding JWT's %s is %r, which is not a "
                                           "finite number" % (claim, value))
        if claim == "exp" and now > value + max_skew_seconds:
            return _refuse("kb_freshness", "the key binding JWT %s %.0f seconds ago (exp), "
                                           "outside the %d second allowance"
                                           % (human, now - value, max_skew_seconds))
        if claim == "nbf" and now < value - max_skew_seconds:
            return _refuse("kb_freshness", "the key binding JWT is %s for another %.0f "
                                           "seconds (nbf), outside the %d second allowance"
                                           % (human, value - now, max_skew_seconds))

    # sd_hash covers the issuer JWT AND every disclosure presented with it, up to and
    # including the final tilde. It is what stops a presentation being re-cut with a
    # different set of disclosures under a key binding that was signed over another set.
    presented = presentation.rsplit("~", 1)[0] + "~"
    expected_sd_hash = b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())
    if kb_payload.get("sd_hash") != expected_sd_hash:
        return _refuse("sd_hash", "the key binding JWT's sd_hash does not match the SHA-256 "
                                  "of what was actually presented: the disclosures are not "
                                  "the set the holder signed over")

    orphans = set(by_digest) - used
    if orphans:
        return _refuse("disclosure", "%d disclosure(s) were presented that resolve to nothing "
                                     "in the credential" % len(orphans))

    # 4. transaction data, last, so every refusal above keeps the order and the reason it had.
    bound = None
    if transaction_data is not None:
        bound = _check_transaction_data(kb_payload, transaction_data)
        if isinstance(bound, Verdict):
            return bound

    return Verdict(True, claims=claims,
                   revocation=_revocation_state(payload, status_resolver, issuer),
                   disclosed=disclosed, transaction_data=bound, **signer)
