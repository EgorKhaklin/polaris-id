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
import time

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
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
ISSUER_TYP = "dc+sd-jwt"
KB_TYP = "kb+jwt"

#: ES256 only, which is HAIP's floor and its ceiling for the mandatory set. Naming the
#: algorithm in a list rather than reading it out of the header is deliberate: `alg` is
#: attacker-controlled, and a verifier that follows it can be walked down to `none`.
ACCEPTED_ALGS = ("ES256",)

#: Claim names a disclosure may never carry. draft-ietf-oauth-sd-jwt-vc: "iss, nbf, exp,
#: cnf, vct, status ... MUST be included in the SD-JWT and MUST NOT be included in the
#: Disclosures"; draft-ietf-oauth-selective-disclosure-jwt reserves `_sd`, `_sd_alg` and
#: `...` structurally.
#:
#: Refusing the NAME rather than only a collision is the stronger rule and the necessary
#: one. A collision check alone catches a disclosure that overwrites `iss`, and misses one
#: that INTRODUCES `exp` where the issuer set none, which puts a holder-chosen expiry into
#: the claims a relying party reads. `cnf` is the sharpest: a disclosed `cnf` returns a key
#: that is not the key the key binding was checked against, whether or not the issuer set
#: one. Measured 2026-09-17; every one of these verified as authentic before.
_DISCLOSURE_FORBIDDEN_NAMES = frozenset(
    ("iss", "nbf", "exp", "cnf", "vct", "status", "iat", "_sd", "_sd_alg", "..."))

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
if _HAVE_CRYPTO:
    _ISSUER_EKUS = frozenset((
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
    ))
else:  # pragma: no cover
    _ISSUER_EKUS = frozenset()


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

    Silence is the problem, not the absence of a fetch. Fetching a status list is an online
    operation with a timeout, a cache and a failure mode, and it is not what this package does
    today. Saying so costs nothing and is the difference between a bounded claim and an
    overstated one.
    """

    __slots__ = ("authentic", "code", "reason", "claims", "revocation")

    def __init__(self, authentic, code="", reason="", claims=None, revocation=None):
        self.authentic = authentic
        self.code = code
        self.reason = reason
        self.claims = claims or {}
        self.revocation = revocation

    def __repr__(self):
        if self.authentic:
            return "Verdict(authentic, %d claim(s), revocation=%s)" % (
                len(self.claims), (self.revocation or {}).get("state", "n/a"))
        return "Verdict(refused, %s: %s)" % (self.code, self.reason)

    def as_dict(self):
        return {"authentic": self.authentic, "code": self.code, "reason": self.reason,
                "claims": self.claims, "revocation": self.revocation}


#: The three states a relying party has to be able to tell apart. A verifier that collapses
#: any two of them is overstating one of them.
NO_STATUS_CLAIM = "no_status_claim"        # the credential points at no revocation list
NOT_EVALUATED = "not_evaluated"            # it points at one and this verifier did not read it
UNSUPPORTED_STATUS = "unsupported_status"  # it points at one in a form this code cannot read


def _revocation_state(payload):
    """What this verifier can say about revocation, which is currently never "not revoked".

    Reads only the credential's own issuer-signed `status` claim. Opens no socket, and the
    state it returns says so, because a caller that cannot distinguish "the issuer published
    no revocation list" from "there is one and nobody looked" cannot make a decision about
    either.
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
        return {"state": NOT_EVALUATED, "checked": False,
                "uri": ref["uri"], "idx": ref["idx"],
                "reason": "the credential names a Token Status List at %s index %d. This "
                          "verifier did not fetch it, so whether the issuer has revoked this "
                          "credential is UNKNOWN, not false" % (ref["uri"], ref["idx"])}
    return {"state": UNSUPPORTED_STATUS, "checked": False, "uri": None, "idx": None,
            "reason": "the credential carries a status claim in a form this verifier does not "
                      "recognise, so its revocation state is unknown"}


def _refuse(code, reason):
    return Verdict(False, code, reason)


# --------------------------------------------------------------------------- encoding

def b64u_decode(value):
    """Decode base64url without padding. Raises ValueError on anything malformed."""
    if isinstance(value, str):
        value = value.encode("ascii", "strict")
    pad = -len(value) % 4
    try:
        return base64.urlsafe_b64decode(value + b"=" * pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not base64url: %s" % exc) from exc


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


def _json_bounded(raw, what):
    """`json.loads` with the two bounds it has none of: size and nesting depth."""
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
    return json.loads(text, parse_constant=_no_constants)


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


def _issuer_public_key(header, issuer_jwks, trust_anchors):
    """The key the issuer JWS is checked under, or a reason it cannot be established.

    Two ways, both explicit: an `x5c` chain whose leaf chains to a configured trust anchor,
    or a JWK the caller configured out of band. A verifier that takes the key from the token
    without either is not verifying anything, so there is no third way and no fallback.
    """
    chain = header.get("x5c")
    if chain:
        if not isinstance(chain, list) or not chain:
            return None, "x5c is present but is not a non-empty array"
        try:
            leaf = load_der_x509_certificate(base64.b64decode(chain[0]))
        except Exception as exc:  # noqa: BLE001  any parse failure is the same refusal
            return None, "the x5c leaf certificate does not parse: %s" % exc
        if not trust_anchors:
            return None, ("the credential presents an x5c chain and no trust anchor is "
                          "configured, so nothing can be said about who signed it")
        for anchor in trust_anchors:
            if _chains_to(leaf, anchor):
                return leaf.public_key(), ""
        return None, "the x5c leaf does not chain to any configured trust anchor"
    if issuer_jwks:
        kid = header.get("kid")
        for jwk in issuer_jwks:
            # A configured JWK list is operator input and can hold anything. Reading `kid`
            # off a string raised AttributeError straight out of a function whose contract
            # says it never raises on bad input, which on the wire is a broken connection
            # where a 4xx belongs.
            if not isinstance(jwk, dict):
                continue
            if kid and jwk.get("kid") and jwk["kid"] != kid:
                continue
            try:
                return _es256_public_key(jwk), ""
            except ValueError:
                continue
        return None, "no configured issuer JWK matches this credential's kid"
    return None, ("the credential carries no x5c and no issuer JWK is configured, so there "
                  "is no key to check the issuer signature against")


def _chains_to(leaf, anchor):
    """Is `leaf` signed by `anchor`? One link, deliberately.

    A full path builder is a different piece of software with its own failure modes. The
    conformance profile registers the anchor out of band and sends the leaf alone, which is
    exactly one link, and a verifier that quietly accepted a longer chain it had not checked
    would be worse than one that says it only does this.
    """
    try:
        anchor.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                   ec.ECDSA(leaf.signature_hash_algorithm))
    except Exception:  # noqa: BLE001  wrong key, wrong algorithm, malformed: all one answer
        return False
    if leaf.issuer != anchor.subject:
        return False

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
    now = _utcnow()
    try:
        not_before = leaf.not_valid_before_utc
        not_after = leaf.not_valid_after_utc
    except AttributeError:  # pragma: no cover - cryptography < 42
        not_before = leaf.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = leaf.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if not (not_before <= now <= not_after):
        return False

    # digitalSignature, when the certificate states a KeyUsage at all. A certificate that
    # says what it may be used for and does not say "sign" is not a signing certificate.
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            return False
    except x509.ExtensionNotFound:
        pass
    except Exception:  # noqa: BLE001  a malformed extension is not a usable permission
        return False

    # And an extended key usage that names purposes without naming this one. serverAuth
    # alone is the TLS certificate case above.
    try:
        ekus = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        oids = set(ekus)
        if (x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in oids
                and not oids & _ISSUER_EKUS):
            return False
    except x509.ExtensionNotFound:
        pass
    except Exception:  # noqa: BLE001
        return False
    return True


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


class _TooDeep(ValueError):
    """The resolver hit its depth cap. A ValueError so existing handlers see it."""


def _resolve(node, by_digest, used, collisions=None, depth=0, memo=None):
    """Rebuild the claims by substituting disclosed values for the digests standing in.

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
            out[key] = _resolve(value, by_digest, used, collisions, depth + 1, memo)
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
                if digest not in memo:
                    memo[digest] = _resolve(disclosure[2], by_digest, used, collisions,
                                            depth + 1, memo)
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
                    if key not in memo:
                        memo[key] = _resolve(disclosure[1], by_digest, used, collisions,
                                             depth + 1, memo)
                    out.append(memo[key])
                continue
            out.append(_resolve(item, by_digest, used, collisions, depth + 1, memo))
        return out
    return node


# ------------------------------------------------------------------------ the verifier

def verify_presentation(presentation, *, expected_nonce, expected_audience,
                        issuer_jwks=None, trust_anchors=None, now=None,
                        max_skew_seconds=DEFAULT_MAX_SKEW_SECONDS,
                        require_key_binding=True, expected_vct=None):
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
    if header.get("typ") not in (ISSUER_TYP, "vc+sd-jwt"):
        return _refuse("issuer_typ", "the issuer JWT declares typ=%r, and this verifier only "
                                     "checks %r" % (header.get("typ"), ISSUER_TYP))
    if header.get("alg") not in ACCEPTED_ALGS:
        return _refuse("issuer_alg", "the issuer JWT declares alg=%r, which is not in the "
                                     "accepted set %r" % (header.get("alg"), ACCEPTED_ALGS))
    key, why = _issuer_public_key(header, issuer_jwks, trust_anchors)
    if key is None:
        return _refuse("issuer_key", why)
    if not _verify_es256(key, signing_input, signature):
        return _refuse("issuer_signature", "the issuer signature over the credential does "
                                           "not verify under the trusted issuer key")

    if expected_vct is not None:
        wanted = ({expected_vct} if isinstance(expected_vct, str)
                  else {v for v in expected_vct if isinstance(v, str)})
        if payload.get("vct") not in wanted:
            return _refuse("vct", "the credential is of type %r and this request asked for "
                                  "%s: a credential of the wrong type is not an answer to "
                                  "the question that was put"
                                  % (payload.get("vct"), sorted(wanted)))

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
        # A 3-element disclosure names a claim. An object-property disclosure may not name
        # one of the registered claims the credential's own integrity rests on, whether or
        # not the payload already carries it.
        if len(parsed) == 3 and parsed[1] in _DISCLOSURE_FORBIDDEN_NAMES:
            return _refuse("disclosure",
                           "a disclosure is named %r, which the specification requires to be "
                           "in the signed credential and never selectively disclosed. A "
                           "holder-supplied %r is not one this verifier will hand on"
                           % (parsed[1], parsed[1]))
        by_digest[digest] = parsed

    # AFTER parsing, not before: a recursive disclosure's inner digest is reachable only
    # through the outer disclosure's decoded value, so the committed set cannot be computed
    # until the disclosures are in hand. The fixpoint only ever follows digests that are
    # ALREADY committed, so a disclosure the issuer never vouched for cannot widen it.
    committed = _committed_digests(payload, by_digest)
    for digest in by_digest:
        if digest not in committed:
            return _refuse("disclosure", "a disclosure was presented that the issuer never "
                                         "committed to: its digest appears nowhere in the "
                                         "signed payload")

    used = set()
    collisions = []
    try:
        claims = _resolve(payload, by_digest, used, collisions)
    except _TooDeep as exc:
        return _refuse("disclosure", str(exc))
    if collisions:
        # SD-JWT section 9.3. The clear-text claims go in first and the disclosed ones
        # second, so before this check a disclosure named `iss` simply replaced the issuer in
        # the returned claims and the verdict stayed authentic. `cnf` was the sharpest: the
        # claims named a key that was not the key the key binding was checked against.
        return _refuse("disclosure",
                       "a disclosure is named %r, which the credential already carries in "
                       "clear text. A disclosure that overwrites an existing claim is "
                       "refused rather than applied" % collisions[0])

    # 3. key binding, which is what makes this a presentation rather than a copy
    if not kb_jwt:
        if require_key_binding:
            return _refuse("kb_missing", "the presentation carries no key binding JWT, so "
                                         "nothing ties it to the holder who presented it")
        return Verdict(True, claims=claims,
                       revocation=_revocation_state(payload))

    cnf = payload.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        return _refuse("kb_cnf", "the credential carries a key binding JWT but no cnf.jwk to "
                                 "check it against")
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

    return Verdict(True, claims=claims, revocation=_revocation_state(payload))
