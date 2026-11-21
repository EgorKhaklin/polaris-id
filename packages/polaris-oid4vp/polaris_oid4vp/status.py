# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""status.py -- decide a Token Status List token. Pure, and it opens no socket.

draft-ietf-oauth-status-list (at -20, past working group last call, not yet an RFC) is the
mechanism SD-JWT VC, CWT and ISO mdoc all reference for revocation. This decides one: given a
Status List Token and an index, what did the issuer publish about that credential.

WHY THIS IS HERE AND NOT IN `sdjwt.py`. That file promises it "touches no socket, reads no
configuration file and knows nothing about HTTP", and the promise is worth keeping. So does
this: `decide` is handed the token, and `decide_by_fetching` is handed a `fetch` callable.
Timeouts, retries, connection limits and caching belong to the caller, because they are policy
and because only the caller knows what a slow or failed status check costs them.

THE THING THIS EXISTS TO PREVENT. A verifier that cannot reach the status list, shrugs, and
reports the credential as fine. It is the obvious failure and it is what the pressure of
production pushes you toward, because refusing traffic when a third party's server is down is
expensive. The answer is not to choose a behaviour on the relying party's behalf. It is to say
which of these happened and let them decide:

    checked, VALID / INVALID / SUSPENDED   the issuer published a status and it says so
    no_authority                           nobody is stated as entitled to say, so nothing
                                           was asked and nothing was fetched
    unreachable                            somebody is entitled, and we could not get it
    a refusal code                         a list was obtained and is not usable as evidence

"I could not reach the list" is not "not revoked". A verdict that cannot tell them apart has
thrown away the only fact the relying party needed.

WHO MAY PUBLISH STATUS FOR WHOM is not settled by the draft, which is why `StatedAuthority`
exists. Section 11.3 says the Status Issuer MAY reuse the credential issuer's key when they
are the same entity, and that when they differ their certificates SHOULD share a Certificate
Authority. Both are recommendations. `iss` is not even a required claim of a Status List
Token, so the token frequently does not name its own issuer, and the only binding it carries
is `sub` equal to the `uri` the credential named. Fetch that URI and believe whatever signed
the response and you have asked DNS an authorization question. So it is stated or it is
refused.

Research, adversaries and the decision record: lab/strategy/001-token-status-list.md.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
import urllib.parse
import zlib

from . import sdjwt
from .sdjwt import bounded_reason

#: How far ahead of this verifier's clock a status list token's `iat` may be. Zero until
#: 2026-09-28: an issuer that signs its list when it is fetched (the Polaris issuer does), fetched
#: across a second boundary, was refused as dated in the future, and so was any list from a
#: machine whose clock runs ahead. Found presenting a Polaris wallet copy through walt.id
#: (lab/strategy/005, S6). The same allowance sdjwt.py gives a key binding JWT and exp/nbf; a
#: token dated further ahead is still refused.
MAX_IAT_SKEW_SECONDS = 300

#: Status values the draft defines. 0x03 and 0x0C-0x0F are application-specific (draft -21,
#: section 7.1; 0x0B left that range in -14); everything else is reserved. An unknown value is
#: reported by number and NOT folded into "valid", because a status this code does not
#: understand is not a status it may act on.
VALID, INVALID, SUSPENDED = 0, 1, 2
_MEANING = {VALID: "VALID", INVALID: "INVALID", SUSPENDED: "SUSPENDED"}

#: The type header a Status List Token must carry. A plain JWT that happens to have a
#: status_list claim is not one, and accepting it would let any signed object this issuer ever
#: produced be replayed as a status list.
STATUS_LIST_TYP = "statuslist+jwt"

#: Bounded decompression. `lst` is attacker-influenced: it arrives over the network from a URI
#: named inside the credential. zlib will happily turn a few hundred bytes into gigabytes, and
#: a verifier that dies is a verifier that fails open for every OTHER credential in the queue.
#: 8 MiB holds a 1-bit list of 67 million credentials, which is larger than any real population
#: this would be pointed at.
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024

#: The token itself is a JWT fetched from a URI. Same reasoning, smaller number.
MAX_TOKEN_BYTES = 2 * 1024 * 1024

#: The bounds `json.loads` has none of. `sdjwt.py` next door learned this on 2026-09-17:
#: 2,780 bytes of `[[[[...]]]]` raised RecursionError straight out of a verifier documented
#: never to raise, and RecursionError is not a ValueError, so every `except ValueError`
#: missed it. This module was promoted out of lab/ on 2026-09-19 WITHOUT that lesson and had
#: the same defect from its first minute in a published package: a status list token nesting
#: 20,000 objects deep raised out of `decide`, which says "Total on hostile input" on its
#: first line.
#:
#: Catching RecursionError would be the wrong repair, for the reason recorded beside the
#: sibling: it fires at an arbitrary point depending on how much stack the caller already
#: used, so the same input is accepted from one call site and raises from another, and an
#: interpreter that has just unwound a stack overflow is not where security decisions should
#: be made. Refusing the SHAPE before parsing is deterministic.
#:
#: The header is a small JSON document, and 64 KiB and 64 levels are far past anything honest
#: for it. The payload is not small: the compressed array is inside it, base64url-encoded in
#: `lst`. It was held to the same 64 KiB until 2026-10-04, which refused lists the draft itself
#: sizes as ordinary (Appendix B: 2^20 entries at 10% revoked is 67.6 KB compressed). The
#: OpenWallet Foundation's @sd-jwt/jwt-status-list 0.19.0 signs that list as a 97,153-byte
#: payload, and every credential on it was undecidable here (lab/interop/status-list). The
#: payload's size bound is now the token's own; its depth bound is unchanged.
MAX_JSON_BYTES = 64 * 1024
MAX_PAYLOAD_JSON_BYTES = MAX_TOKEN_BYTES
MAX_JSON_DEPTH = 64


def _nesting_depth(text):
    """The deepest bracket nesting in a JSON document, ignoring brackets inside strings.

    A linear scan, so it costs nothing next to the parse it guards.
    """
    depth = maximum = 0
    in_string = escaped = False
    for ch in text:
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


def _json_bounded(raw, what, limit=MAX_JSON_BYTES):
    """`json.loads` with the three bounds it has none of: size, depth and bare constants."""
    if len(raw) > limit:
        raise ValueError("the %s is %d bytes, over the %d byte limit"
                         % (what, len(raw), limit))
    text = raw.decode("utf-8", "strict") if isinstance(raw, bytes) else raw
    if _nesting_depth(text) > MAX_JSON_DEPTH:
        raise ValueError("the %s nests deeper than %d levels" % (what, MAX_JSON_DEPTH))

    # Python's json accepts the bare literals NaN, Infinity and -Infinity, and they are
    # floats, so they walk past `isinstance(x, (int, float))` downstream. Every numeric
    # field here requires a bare `int` and would refuse them anyway, which is exactly why
    # they are refused at the door instead: a defence that depends on every downstream
    # guard staying right is one field away from not being a defence.
    def _no_constants(literal):
        raise ValueError("the %s contains the non-JSON literal %s" % (what, literal))
    return json.loads(text, parse_constant=_no_constants)


class Verdict(dict):
    """A dict, so callers can treat it as data, with the two questions kept apart. Its reason is
    at most sdjwt.REASON_MAX characters, cut as a presentation verdict's is: it can quote the
    list token's own fields, the status URI and what a resolver or a fetch raised."""

    def __init__(self, *args, **fields):
        super().__init__(*args, **fields)
        if "reason" in self:
            self["reason"] = bounded_reason(self["reason"])

    @property
    def checked(self):
        return self["checked"]


def _refuse(code, reason):
    return Verdict(checked=False, status=None, meaning=None, fresh=None, age_seconds=None,
                   stale=None, authority=None, code=code, reason=reason)


# --------------------------------------------------------------------------- authority
#
# WHO IS ENTITLED TO SAY A CREDENTIAL IS REVOKED.
#
# Measured against draft-20 (2026-04-20) rather than assumed. The draft does not settle this
# and says so: section 11.3, "Key Resolution and Trust Management", notes that when the Status
# Issuer and the credential's issuer are the same entity the same key MAY be reused, and that
# when they differ their certificates SHOULD come from the same Certificate Authority with an
# extended key usage on the Status Issuer's. Both are recommendations, both presume x.509, and
# neither is a rule a verifier can apply on its own.
#
# It is worse than that for anyone hoping to infer it. `iss` is NOT a required claim of a
# Status List Token: section 5.1 requires `sub`, `iat` and `status_list` only. So the token
# frequently does not name its own issuer, and the sole binding it carries is `sub` == the
# `uri` the credential named. A verifier that fetches that URI and believes whatever signed
# the response is trusting DNS and TLS to answer an authorization question.
#
# Polaris's answer is the one its architecture already takes everywhere else: do not infer it,
# require it to be stated, and put the basis in the verdict. Three bases are honest.
#
#   SAME_KEY    the status list verifies under the very key that verified the credential's
#               issuer signature. Nothing was delegated and nothing needs to be configured.
#
#   STATED      an operator configured, in advance, that a named key may publish status for a
#               named issuer at a named URI, and why. A relying party that cannot say who it
#               is trusting has not made a trust decision.
#
#   ANCHORED    an operator configured, in advance, that for credentials whose issuer chain
#               ended at one named anchor, status lists under one URI prefix may be signed by a
#               certificate that chains to a second named anchor, and why (added 2026-11-21).
#               A trust list names a provider's two services and their two anchors, one for
#               issuance and one for revocation; the pair is taken from one entry of it, and
#               neither `iss` nor DNS is asked who the provider is.
#
# Anything else is refused as `no_authority`, which is NOT the same as a valid credential.

SAME_KEY = "same_key"
STATED = "stated"
ANCHORED = "anchored"


class Unauthorized:
    """What an authority returns to refuse a grant and say why: false, as None is, so a caller
    that reads any false answer as no authority still does, and `decide` gives this reason in
    its `no_authority` refusal instead of the general one."""

    __slots__ = ("reason",)

    def __init__(self, reason):
        self.reason = reason

    def __bool__(self):
        return False


def _takes_credential_anchor(callable_):
    """True only when `callable_` declares `takes_credential_anchor = True`. A resolver or an
    authority written before the keyword existed is called exactly as it was, with no keyword it
    does not take, and a declaration of any other value is not one."""
    return getattr(callable_, "takes_credential_anchor", False) is True


class StatedAuthority:
    """An explicit table: who may publish status for whom, and on whose say-so.

    Deliberately not a resolver. There is no lookup, no fetch and no inference: an entry
    exists because somebody put it there and wrote down why. That is the whole point, and it
    is why this is a class of about twenty lines rather than a protocol.
    """

    def __init__(self):
        self._entries = {}

    def state(self, *, credential_issuer, status_uri, verify, why):
        """Record that `verify` may decide status lists at `status_uri` for this issuer."""
        if not (credential_issuer and status_uri and callable(verify) and why):
            raise ValueError("a stated delegation needs an issuer, a uri, a verifier and a "
                             "reason; an entry nobody can explain is not a trust decision")
        self._entries[(credential_issuer, status_uri)] = (verify, why)
        return self

    def __call__(self, *, credential_issuer, status_uri, header, issuer_key_verify=None):
        """Return (verify_callable, basis, why) or None when no authority is established."""
        if issuer_key_verify is not None:
            return (issuer_key_verify, SAME_KEY,
                    "the status list is signed by the key that signed the credential")
        found = self._entries.get((credential_issuer, status_uri))
        if found is None:
            return None
        verify, why = found
        return (verify, STATED, why)


#: A DNS host as an https URI's authority names it, held to ASCII lowercase: an internationalized
#: name is compared as the A-label it is written as, and a trailing dot is part of the name.
_DNS_HOST = re.compile(r"[a-z0-9.-]+\Z")


def _https_parts(uri, what):
    """(host, port, path) of an https URI in the one form an anchored entry compares, or
    ValueError naming the rule it breaks. The host is lowercased and the port kept as written
    ("" when none is); nothing else is normalised, so two spellings of one place compare equal
    only when they are written alike, and anything that could be read two ways is refused."""
    if not isinstance(uri, str) or not uri or not uri.isascii():
        raise ValueError("%s is not a non-empty ASCII string" % what)
    if "\\" in uri:
        raise ValueError("%s carries a backslash, which some readers take for a slash" % what)
    if "#" in uri:
        raise ValueError("%s carries a fragment" % what)
    if "?" in uri:
        raise ValueError("%s carries a query" % what)
    split = urllib.parse.urlsplit(uri)
    if split.scheme != "https":
        raise ValueError("%s is not https" % what)
    _userinfo, at, authority = split.netloc.rpartition("@")
    if at:
        raise ValueError("%s carries userinfo" % what)
    host, colon, port = authority.partition(":")
    if colon and not port.isdigit():
        raise ValueError("%s names an empty or non-numeric port" % what)
    host = host.lower()
    if not _DNS_HOST.match(host):
        raise ValueError("%s names no DNS host" % what)
    segments = split.path.split("/")
    if "." in segments or ".." in segments:
        raise ValueError("%s has a dot segment in its path" % what)
    if "%2f" in split.path.lower() or "%2e" in split.path.lower():
        raise ValueError("%s percent-encodes a slash or a dot in its path" % what)
    return host, port, split.path


def _der_sha256(cert):
    """The SHA-256 of a certificate's DER encoding: what names an anchor in an anchored entry."""
    return hashlib.sha256(cert.public_bytes(sdjwt.serialization.Encoding.DER)).digest()


def _organizations(cert):
    """The organizationName values of a certificate's subject, in order; [] when it has none."""
    oid = sdjwt.x509.oid.NameOID.ORGANIZATION_NAME
    return [attribute.value for attribute in cert.subject.get_attributes_for_oid(oid)]


def _refuses_every_signature(signing_input, signature, header):
    """The verify callable of a grant made before the token is in hand: that grant answers only
    whether the URI may be fetched, and no signature is judged under it."""
    return False


class AnchoredAuthority:
    """An explicit table, as StatedAuthority is: for credentials whose issuer chain ended at
    `credential_anchor`, status lists under `status_uri_prefix` may be signed by a certificate
    whose x5c chains to `status_anchor`, on the stated `why`.

    It is for an issuer whose status list is signed under a revocation-service CA of its own,
    beside its issuing CA, both named in one provider entry of a trust list (the German EUDI PID
    verifier guidelines, rows V-19 and V-20). No lookup, no fetch and no inference: the operator
    takes both anchors from that one entry and states them here.

    The anchors are certificates (`cryptography.x509.Certificate`). They must differ, and neither
    may certify the other: a status anchor that signed the issuance anchor would let a list
    signed under the issuance CA's own keys pass as the revocation service's. The prefix is an
    https URI whose path ends in "/"; a status URI is under it when it has the same host and
    port, written alike, and its path begins with the prefix's.

    `decide` asks it twice. Before the fetch (`header` None) it answers only whether this URI may
    be fetched for this credential anchor, with a grant under which no signature verifies. With
    the token's header it requires an x5c whose leaf chains to the status anchor under the same
    chain rules an issuer's x5c is held to, a key usage on that leaf that states
    digitalSignature, a leaf that does not also chain to the credential anchor, and an
    organizationName on that leaf equal to the credential signer's; it then grants the leaf's key
    for ES256. There is no same-key branch.
    """

    takes_credential_anchor = True

    def __init__(self):
        self._entries = []

    def state(self, *, credential_anchor, status_uri_prefix, status_anchor, why):
        """Record one anchored delegation. ValueError when it is not one this class can hold."""
        if credential_anchor is None or status_anchor is None or not status_uri_prefix or not why:
            raise ValueError("an anchored delegation needs a credential anchor, a status URI "
                             "prefix, a status anchor and a reason; an entry nobody can explain "
                             "is not a trust decision")
        for what, cert in (("the credential anchor", credential_anchor),
                           ("the status anchor", status_anchor)):
            if not isinstance(cert, sdjwt.x509.Certificate):
                raise ValueError("%s is not an X.509 certificate" % what)
        if _der_sha256(credential_anchor) == _der_sha256(status_anchor):
            raise ValueError("the credential anchor and the status anchor are one certificate")
        if sdjwt._signed_by(credential_anchor, status_anchor):
            raise ValueError("the status anchor certifies the credential anchor")
        if sdjwt._signed_by(status_anchor, credential_anchor):
            raise ValueError("the credential anchor certifies the status anchor")
        prefix = _https_parts(status_uri_prefix, "the status URI prefix")
        if not prefix[2].endswith("/"):
            raise ValueError("the status URI prefix's path does not end in /")
        self._entries.append((_der_sha256(credential_anchor), prefix, credential_anchor,
                              status_anchor, why))
        return self

    def __call__(self, *, credential_issuer, status_uri, header, issuer_key_verify=None,
                 credential_anchor=None, credential_leaf=None, now=None):
        """(verify, ANCHORED, why), or an Unauthorized saying why there is no grant."""
        if credential_anchor is None:
            return Unauthorized("no credential anchor reached this authority")
        try:
            anchor_id = _der_sha256(credential_anchor)
        except Exception:                          # an anchor that does not encode names nothing
            return Unauthorized("the credential anchor does not encode as DER")
        entries = [entry for entry in self._entries if entry[0] == anchor_id]
        if not entries:
            return Unauthorized("no anchored entry names the anchor this credential's issuer "
                                "chain ended at")
        try:
            host, port, path = _https_parts(status_uri, "the status URI")
        except ValueError as exc:
            return Unauthorized(str(exc))
        entries = [entry for entry in entries
                   if host == entry[1][0] and port == entry[1][1] and path.startswith(entry[1][2])]
        if not entries:
            return Unauthorized("the status URI %s is under no prefix stated for this credential "
                                "anchor" % status_uri)
        if header is None:
            return (_refuses_every_signature, ANCHORED, entries[0][4])
        refusals = []
        for _, _, issuance_anchor, status_anchor, why in entries:
            verify, refusal = _status_signer(header, status_anchor, issuance_anchor,
                                             credential_leaf, now)
            if verify is not None:
                return (verify, ANCHORED, why)
            refusals.append(refusal)
        return Unauthorized("the status list token's signer is not one the stated status anchor "
                            "certifies: %s" % "; ".join(refusals))


def _status_signer(header, status_anchor, issuance_anchor, credential_leaf, now):
    """(verify, "") granting the status list token's x5c leaf for ES256, or (None, why not)."""
    if "x5c" not in header:
        return None, "the token carries no x5c, so no certificate names its signer"
    keys, why, certified = sdjwt._issuer_public_keys(header, None, [status_anchor], now)
    if not keys:
        return None, why
    leaf = certified[0]
    # The one rule a status signer is held to beyond an issuer's: a key usage, and one that
    # states digitalSignature. `_chains_to` refuses a key usage without it; a leaf that states
    # none is not restricted there, and here it is not a status signer.
    try:
        leaf.extensions.get_extension_for_class(sdjwt.x509.KeyUsage)
    except sdjwt.x509.ExtensionNotFound:
        return None, "the signer's certificate states no key usage, so it is not shown to sign"
    why = _under_the_credential_anchor(header["x5c"], issuance_anchor)
    if why:
        return None, why
    if credential_leaf is None:
        return None, "no credential signer's certificate reached this authority to match"
    signer_organizations = _organizations(leaf)
    if not signer_organizations or signer_organizations != _organizations(credential_leaf):
        return None, ("the signer's organizationName %s is not the credential signer's %s"
                      % (signer_organizations, _organizations(credential_leaf)))
    key = keys[0]

    def verify(signing_input, signature, token_header):
        return (token_header.get("alg") in sdjwt.ACCEPTED_ALGS
                and sdjwt._verify_es256(key, signing_input, signature))
    return verify, ""


def _under_the_credential_anchor(chain, credential_anchor):
    """"" when no certificate in `chain`, the token's x5c as sent, carries the credential
    anchor's key or a signature that key made; else the refusal naming the first that does.

    `state` refuses a status anchor that signs the credential anchor, or is signed by it, and
    it sees only those two certificates. A status anchor further up the credential anchor's
    own path (a root, a policy CA, then the credential anchor) passes it, and a leaf the
    credential anchor issued then chains to the status anchor through that path; the path
    must pass through the credential anchor's key, so a certificate the token sends either
    carries it or was signed with it. Asking whether the chain verifies to the credential
    anchor instead misses exactly this case: the anchor is in the x5c, and that is refused
    as an anchor sent in x5c, which reads as "does not chain" (the review of 2026-11-21).
    The chain parsed when the status anchor's check read it, so one that no longer does is
    refused as unreadable rather than passed."""
    der, spki = sdjwt.serialization.Encoding.DER, sdjwt.serialization.PublicFormat.SubjectPublicKeyInfo
    anchor_key = credential_anchor.public_key()
    anchor_spki = anchor_key.public_bytes(der, spki)
    for position, item in enumerate(chain):
        try:
            cert = sdjwt.load_der_x509_certificate(base64.b64decode(item))
            carries = cert.public_key().public_bytes(der, spki) == anchor_spki
        except Exception:  # noqa: BLE001  any parse failure is the same refusal
            return "x5c certificate %d does not parse, so its issuer cannot be ruled out" % position
        if carries:
            return ("the signer's certificate also chains to the credential anchor: x5c "
                    "certificate %d carries the credential anchor's key" % position)
        try:
            anchor_key.verify(cert.signature, cert.tbs_certificate_bytes,
                              sdjwt.ec.ECDSA(cert.signature_hash_algorithm))
        except Exception:  # noqa: BLE001  wrong key, wrong algorithm: not signed with it
            continue
        return ("the signer's certificate also chains to the credential anchor: x5c certificate "
                "%d was signed with the credential anchor's key" % position)
    return ""


def _b64u(value, what):
    """Decode base64url without padding, raising ValueError with a useful `what`."""
    if isinstance(value, str):
        value = value.encode("ascii", "strict")
    pad = -len(value) % 4
    try:
        raw = base64.urlsafe_b64decode(value + b"=" * pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("%s is not valid base64url: %s" % (what, exc))
    # Canonical only, as sdjwt.b64u_decode (2026-09-25).
    if base64.urlsafe_b64encode(raw).rstrip(b"=") != value:
        raise ValueError("%s is not canonical base64url" % what)
    return raw


def _inflate_bounded(raw, limit=MAX_DECOMPRESSED_BYTES):
    """zlib-inflate `raw`, refusing to produce more than `limit` bytes.

    decompressobj with a max_length is the only form that refuses a bomb without first
    building it. `zlib.decompress` has no bound and is the wrong call here however tidy it
    looks. The length check after flush() is not a spare: a stream whose trailer is cut off
    leaves no unconsumed tail, so the first bound passes it and flush() produces the rest.
    And the stream must END: a truncated one inflated to its data and was accepted, where
    zlib.decompress refuses it (both found by the review of 2026-09-30).
    """
    obj = zlib.decompressobj()
    out = obj.decompress(raw, limit)
    if obj.unconsumed_tail:
        raise ValueError("the status list decompresses to more than %d bytes" % limit)
    out += obj.flush()
    if len(out) > limit:
        raise ValueError("the status list decompresses to more than %d bytes" % limit)
    if not obj.eof:
        raise ValueError("the status list's compressed data is truncated: the stream never ends")
    return out


def status_at(array, index, bits):
    """The status value at `index` in a decompressed status array.

    Bits run from the least significant end of each byte, so for bits=1 the byte 0xB9 holds
    indices 0..7 as 1,0,0,1,1,1,0,1. Getting this backwards is the classic implementation bug
    and it is silent: every status still decodes, just to the wrong credential's answer.

    Raises IndexError when the index is past the end of the array. That is deliberately not a
    status: a list that does not cover an index says nothing about it, and the caller must not
    be able to read the absence as VALID.
    """
    if bits not in (1, 2, 4, 8):
        raise ValueError("bits must be 1, 2, 4 or 8, not %r" % (bits,))
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("index must be a non-negative integer, not %r" % (index,))
    per_byte = 8 // bits
    byte_index = index // per_byte
    if byte_index >= len(array):
        raise IndexError("index %d is past the end of a %d-byte status list (%d entries)"
                         % (index, len(array), len(array) * per_byte))
    offset = (index % per_byte) * bits
    return (array[byte_index] >> offset) & ((1 << bits) - 1)


def _no_anchor_reached():
    return _refuse("no_authority", "no credential anchor reached this authority: it grants only "
                                   "for a credential whose issuer x5c chain ended at a configured "
                                   "trust anchor, so nothing was fetched or believed")


def _ask(authority, *, credential_issuer, status_uri, header, issuer_key_verify,
         credential_anchor, credential_leaf, now):
    """Call `authority`, with the credential's anchor, its signer's certificate and `now` only
    when it declares `takes_credential_anchor = True`."""
    extra = ({"credential_anchor": credential_anchor, "credential_leaf": credential_leaf,
              "now": now} if _takes_credential_anchor(authority) else {})
    return authority(credential_issuer=credential_issuer, status_uri=status_uri, header=header,
                     issuer_key_verify=issuer_key_verify, **extra)


def decide(token, *, index, expected_uri, authority, now, credential_issuer=None,
           issuer_key_verify=None, max_age_seconds=None, credential_anchor=None,
           credential_leaf=None):
    """Decide the status of one referenced credential. Total on hostile input.

    token              the Status List Token, a compact JWS (str or bytes)
    index              the `idx` from the credential's own status claim
    expected_uri       the `uri` from that same claim; must equal the token's `sub`
    authority          callable(credential_issuer=, status_uri=, header=, issuer_key_verify=)
                       returning (verify, basis, why) or None. See StatedAuthority above: the
                       draft does not settle who may publish status for whom, so this is the
                       one thing that must be decided outside and stated.
    now                integer POSIX seconds
    credential_issuer  the `iss` of the credential being checked. Part of the authority key,
                       because a key entitled to publish status for one issuer is not thereby
                       entitled to publish it for another.
    issuer_key_verify  the verifier that checked the credential's own issuer signature, when
                       the caller wants the same-key basis considered.
    max_age_seconds    the caller's own staleness bound, applied on top of the token's `ttl`.
                       A relying party is allowed to be stricter than the issuer.
    credential_anchor  the configured trust anchor the credential's issuer x5c chain ended at,
    credential_leaf    and that chain's leaf (`sdjwt._issuer_public_keys` returns the pair).
                       Handed, with `now`, only to an authority that declares
                       `takes_credential_anchor = True` (AnchoredAuthority does); such an
                       authority with no anchor to be handed is `no_authority`.

    The verdict always carries `checked`. Everything else is meaningful only when it is True,
    and `authority` says on what basis, because "revoked" from a key nobody vetted is not a
    fact about the credential.
    """
    if isinstance(token, str):
        token = token.encode("ascii", "replace")
    if not isinstance(token, (bytes, bytearray)):
        return _refuse("malformed", "the status list token is not bytes or str")
    if not token:
        return _refuse("malformed", "the status list token is empty")
    if len(token) > MAX_TOKEN_BYTES:
        return _refuse("malformed", "the status list token is %d bytes, over the %d byte limit"
                                    % (len(token), MAX_TOKEN_BYTES))
    if not isinstance(now, int) or isinstance(now, bool):
        return _refuse("misconfigured", "now must be an integer POSIX time")
    # The `sub` binding below is half of a token's provenance, and the docstring says the uri
    # MUST equal it. With None it was skipped, so any status list a trusted key ever signed
    # answered for any credential (2026-10-01).
    if not isinstance(expected_uri, str) or not expected_uri:
        return _refuse("misconfigured", "expected_uri, the uri the credential's own status claim "
                                        "names, must be supplied: without it the status list is "
                                        "bound to no credential")

    parts = bytes(token).split(b".")
    if len(parts) != 3:
        return _refuse("malformed", "the status list token is not a compact JWS of three parts")
    try:
        header = _json_bounded(_b64u(parts[0], "the header"), "header")
        payload = _json_bounded(_b64u(parts[1], "the payload"), "payload",
                                MAX_PAYLOAD_JSON_BYTES)
        signature = _b64u(parts[2], "the signature")
    except (ValueError, UnicodeDecodeError) as exc:
        return _refuse("malformed", "the status list token does not parse: %s" % exc)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return _refuse("malformed", "the status list token's header or payload is not an object")

    # TYPE. A Status List Token is a distinct type of object, and the draft says so with a
    # MUST. Without this any signed JWT the issuer ever minted could be offered here, and the
    # ones that happen to carry a status_list claim would be believed.
    if header.get("typ") != STATUS_LIST_TYP:
        return _refuse("typ", "the token declares typ=%r and a status list must declare %r"
                              % (header.get("typ"), STATUS_LIST_TYP))
    # RFC 7515 4.1.11, as for the credential and its key binding JWT: a `crit` naming an
    # extension this implementation does not understand makes the JWS invalid, and it
    # understands none.
    if "crit" in header:
        return _refuse("crit", "the status list token's crit names %r, and this verifier "
                               "implements no JWS extension (RFC 7515 4.1.11)"
                               % (header.get("crit"),))

    # PROVENANCE, first half. `sub` binds the token to the URI the credential named. Without
    # it, a status list legitimately published for one credential population can be served in
    # answer to a query about another, and every index in it decodes to something.
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        return _refuse("sub", "the status list token carries no sub, so it is bound to no URI")
    if subject != expected_uri:
        return _refuse("sub_mismatch",
                       "the credential points at %r and this status list is published for "
                       "%r; it is a real status list for somebody else"
                       % (expected_uri, subject))

    # PROVENANCE, second half, and the half the draft leaves open. Establish WHO is entitled
    # to publish status for this credential's issuer BEFORE checking whether they signed it:
    # a valid signature by an unauthorized key is the attack, not the answer.
    if _takes_credential_anchor(authority) and credential_anchor is None:
        return _no_anchor_reached()
    try:
        granted = _ask(authority, credential_issuer=credential_issuer, status_uri=subject,
                       header=header, issuer_key_verify=issuer_key_verify,
                       credential_anchor=credential_anchor, credential_leaf=credential_leaf,
                       now=now)
    except Exception as exc:                       # a crashing resolver is not a grant
        return _refuse("authority_error",
                       "establishing who may publish this status raised %s: %s"
                       % (type(exc).__name__, exc))
    if not granted:
        return _refuse("no_authority", getattr(granted, "reason", None) or (
                       "no key is stated as entitled to publish status for issuer %r at %r, "
                       "and the draft's own section 11.3 does not settle it; an unvetted "
                       "signature is not an answer about this credential"
                       % (credential_issuer, subject)))
    verify_signature, basis, why = granted

    try:
        ok = verify_signature(b".".join(parts[:2]), signature, header)
    except Exception as exc:                       # a crashing verifier is not a pass
        return _refuse("signature_error",
                       "the signature check raised %s: %s" % (type(exc).__name__, exc))
    if not ok:
        return _refuse("signature", "the status list token's signature did not verify under "
                                    "the key entitled to publish it (%s)" % basis)

    # FRESHNESS. Three separate facts, kept separate: the token may not be used past `exp`;
    # `iat` in the future is nonsense rather than freshness; and `ttl` is the issuer's own
    # statement of how long an answer may be reused, which is not the same as validity.
    iat, exp, ttl = payload.get("iat"), payload.get("exp"), payload.get("ttl")
    for label, value in (("iat", iat), ("exp", exp), ("ttl", ttl)):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            return _refuse("time", "the status list token's %s is %r, which is not an integer; "
                                   "its freshness cannot be evaluated and will not be assumed"
                                   % (label, value))
    if not isinstance(iat, int):
        return _refuse("iat", "the status list token carries no iat, so its answer has no age "
                              "and staleness cannot be evaluated")
    if exp is not None and now >= exp:
        return _refuse("expired", "the status list token expired at %d and it is %d; the draft "
                                  "says it MUST NOT be used" % (exp, now))
    if iat > now + MAX_IAT_SKEW_SECONDS:
        return _refuse("iat_future", "the status list token is dated %d, %d seconds after the "
                                     "current time %d and beyond the %d second allowance for "
                                     "clock differences" % (iat, iat - now, now, MAX_IAT_SKEW_SECONDS))
    # Inside the allowance a token dated ahead of this clock is taken as just issued, not as a
    # negative age that no staleness bound could ever reach.
    age = max(0, now - iat)
    bound = min([b for b in (ttl, max_age_seconds) if b is not None], default=None)
    stale = bound is not None and age > bound

    # THE LIST ITSELF.
    sl = payload.get("status_list")
    if not isinstance(sl, dict):
        return _refuse("status_list", "the token carries no status_list object")
    bits, lst = sl.get("bits"), sl.get("lst")
    if bits not in (1, 2, 4, 8):
        return _refuse("bits", "the status list declares bits=%r; the draft allows 1, 2, 4 "
                               "or 8 and this code will not guess at another" % (bits,))
    if not isinstance(lst, str) or not lst:
        return _refuse("lst", "the status list carries no lst")
    try:
        array = _inflate_bounded(_b64u(lst, "the lst"))
    except (ValueError, zlib.error) as exc:
        return _refuse("lst", "the status list does not decompress: %s" % exc)
    if not array:
        return _refuse("lst", "the status list is empty, so it covers no credential")
    try:
        value = status_at(array, index, bits)
    except IndexError as exc:
        # NOT a status. A list that does not reach this index has said nothing about this
        # credential, and reporting that as VALID is the whole failure mode this file exists
        # to avoid.
        return _refuse("index", str(exc))
    except ValueError as exc:
        return _refuse("index", str(exc))

    return Verdict(checked=True, status=value, meaning=_MEANING.get(value),
                   fresh=not stale, stale=stale, age_seconds=age,
                   authority=basis,
                   code=None,
                   reason=("status %d (%s) published %ds ago on %s authority (%s)%s"
                           % (value, _MEANING.get(value, "application-specific or reserved"),
                              age, basis, why,
                              "; past the %ds bound the issuer or caller set" % bound
                              if stale else "")))


# --------------------------------------------------------------------------- fetching
#
# THE THIRD INCREMENT, AND THE STATE THAT HAS TO STAY SEPARATE.
#
# Everything above decides a token somebody already has. Getting it means a network call,
# and a network call fails in ways that are not answers. The failure mode this exists to
# prevent is the obvious one: a verifier that cannot reach the list, shrugs, and reports the
# credential as fine. It is obvious and it is what almost every implementation does, because
# the alternative is refusing traffic when a third-party endpoint is down, and that pressure
# is real. The answer is not to pick one; it is to report which happened and let the relying
# party set the policy, because only they know what a refusal costs them.
#
# So there are five outcomes and no two of them may collapse:
#
#   checked, status VALID       the issuer published a status and it says valid
#   checked, status INVALID     the issuer published a status and it says revoked
#   no_authority                nobody is stated as entitled to say, so nothing was asked
#   unreachable                 somebody is entitled, and we could not get the answer
#   the refusals above          a token was obtained and is not usable as evidence
#
# `unreachable` is the new one and the whole point. "I could not reach the list" is not "not
# revoked", and a verdict that cannot say which has thrown away the only fact the relying
# party needed in order to decide whether to accept the risk.
#
# STILL NO SOCKET HERE. `fetch` is injected. Timeouts, retries, connection limits and
# caching are the caller's, because they are policy and because polaris-verify promises it
# opens none. What this function owns is the refusal to turn a failed fetch into a verdict.

UNREACHABLE = "unreachable"


def decide_by_fetching(*, index, expected_uri, authority, fetch, now=None,
                       credential_issuer=None, issuer_key_verify=None, max_age_seconds=None,
                       credential_anchor=None, credential_leaf=None):
    """Fetch the status list named by a credential and decide it, or say why not.

    fetch   callable(uri: str) -> bytes. May raise; anything it raises becomes `unreachable`
            rather than an exception out of this function, because a verifier that dies on
            one credential has failed open for every other credential in the queue.
    now     integer POSIX seconds to decide at, or None (the default) to read the clock once the
            token is in hand. A `now` read before the fetch is older than a token the issuer
            signs during it.

    Authority is established BEFORE the fetch, deliberately. If nobody is entitled to publish
    status for this issuer, the answer is `no_authority` and no request is made: asking a URI
    named inside an untrusted credential is how a verifier becomes a scanner pointed at
    whatever an attacker writes into a `uri` field.
    """
    if not isinstance(expected_uri, str) or not expected_uri:
        return _refuse("uri", "the credential names no status list uri to fetch")
    if _takes_credential_anchor(authority) and credential_anchor is None:
        return _no_anchor_reached()
    try:
        granted = _ask(authority, credential_issuer=credential_issuer, status_uri=expected_uri,
                       header=None, issuer_key_verify=issuer_key_verify,
                       credential_anchor=credential_anchor, credential_leaf=credential_leaf,
                       now=now)
    except Exception as exc:
        return _refuse("authority_error",
                       "establishing who may publish this status raised %s: %s"
                       % (type(exc).__name__, exc))
    if not granted:
        return _refuse("no_authority", "%s, so nothing was fetched: a uri named inside an "
                                       "unvetted credential is not a place to send a request"
                       % (getattr(granted, "reason", None) or
                          "no key is stated as entitled to publish status for issuer %r at %r"
                          % (credential_issuer, expected_uri)))
    try:
        token = fetch(expected_uri)
    except Exception as exc:
        return _refuse(UNREACHABLE,
                       "fetching %r raised %s: %s. This is NOT evidence that the credential "
                       "is current; it is the absence of evidence either way"
                       % (expected_uri, type(exc).__name__, exc))
    # WHERE THE BOUNDARY BETWEEN "no answer" AND "a bad answer" SITS. The fetch layer
    # classifies TRANSPORT and `decide` classifies the TOKEN, and a body that is not even
    # shaped like a compact JWS belongs to the first. An error page, an empty body, a JSON
    # `{"error": ...}` are all the endpoint failing to hand over the list, which is
    # `unreachable`; they are not the issuer publishing something broken.
    #
    # The distinction was not here until the mutation drill found the attack too weak to
    # notice its absence: a 404 page reported `malformed`, which reads as "the issuer's list
    # is broken" when the truth is that nobody got a list at all. Both are refusals, so
    # nothing was ACCEPTED either way, and that is exactly why it survived a test asserting
    # only that the verdict was not checked.
    shaped = token if isinstance(token, (bytes, bytearray)) else \
        (token.encode("ascii", "replace") if isinstance(token, str) else None)
    if not shaped or bytes(shaped).count(b".") != 2:
        return _refuse(UNREACHABLE,
                       "fetching %r returned %s, which is not shaped like a status list "
                       "token, so no list was obtained. Whether the credential is revoked is "
                       "unknown, not false"
                       % (expected_uri,
                          "nothing" if not shaped else "%d bytes that are not a compact JWS"
                          % len(bytes(shaped))))
    if now is None:
        now = int(time.time())
    return decide(token, index=index, expected_uri=expected_uri, authority=authority,
                  now=now, credential_issuer=credential_issuer,
                  issuer_key_verify=issuer_key_verify, max_age_seconds=max_age_seconds,
                  credential_anchor=credential_anchor, credential_leaf=credential_leaf)


def make_resolver(authority, fetch, *, max_age_seconds=None):
    """A `status_resolver` for `Verifier` or `sdjwt.verify_presentation` that fetches with
    `fetch` and decides under `authority`. It declares `takes_credential_anchor = True`, so the
    verifier hands it the credential's trust anchor and signer certificate, and it hands them on
    only to an authority that declares the same."""
    def resolve(*, uri, idx, issuer, credential_anchor=None, credential_leaf=None):
        return decide_by_fetching(index=idx, expected_uri=uri, authority=authority, fetch=fetch,
                                  credential_issuer=issuer, max_age_seconds=max_age_seconds,
                                  credential_anchor=credential_anchor,
                                  credential_leaf=credential_leaf)
    resolve.takes_credential_anchor = True
    return resolve


def encode_status_list(statuses, bits=1):
    """Build a `lst` value from a list of status integers. Fixtures and attacks only.

    Here rather than in a test file because both the attack harness and any future promotion
    need it, and two copies of a bit-packer is how the two stop agreeing.
    """
    if bits not in (1, 2, 4, 8):
        raise ValueError("bits must be 1, 2, 4 or 8")
    per_byte = 8 // bits
    size = (len(statuses) + per_byte - 1) // per_byte
    array = bytearray(size)
    for i, s in enumerate(statuses):
        if not 0 <= s < (1 << bits):
            raise ValueError("status %r does not fit in %d bit(s)" % (s, bits))
        array[i // per_byte] |= s << ((i % per_byte) * bits)
    return base64.urlsafe_b64encode(zlib.compress(bytes(array), 9)).rstrip(b"=").decode("ascii")
