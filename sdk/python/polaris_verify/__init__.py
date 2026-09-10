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
import hashlib
import json
import time
import urllib.request
from typing import List, Optional

__version__ = "1.0.0"
ALGORITHM = "ML-DSA-65"   # the default parameter set
# P8.8a: the accepted FIPS 204 parameter sets -> the cryptography witness class. ML-DSA-44 is
# below the floor and is rejected like any unknown algorithm.
ACCEPTED_ALGORITHMS = {"ML-DSA-65": "MLDSA65PublicKey", "ML-DSA-87": "MLDSA87PublicKey"}


def _accepted(alg):
    """True iff `alg` names an accepted parameter set (total over hostile input)."""
    return isinstance(alg, str) and alg in ACCEPTED_ALGORITHMS
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


def _verify_liboqs(digest, sig, pk, alg=ALGORITHM):
    if not _accepted(alg):
        return False
    try:
        import oqs  # type: ignore
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
    whether the pack's key is one of them."""
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
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        return AuthenticityVerdict(False, None, alg, note="signature_hex/public_key_hex are not valid hex")
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
        trusted = pk_hex.lower() in {a.lower() for a in anchors}
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
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
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


def _iso_to_epoch(s):
    from datetime import datetime, timezone
    if not isinstance(s, str):
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


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
    active, all bound to the presented credential's token_value."""
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
    # P9.2: the published anonymity set a holder proves against on their own device.
    "polaris-epoch-leaves/1": ["format", "authority", "epoch_id", "context_id", "merkle_root", "leaf_count", "leaves_root_hex", "issued_at", "expires_at", "algorithm"],
}


@dataclasses.dataclass
class ArtifactVerdict:
    authentic: bool
    fresh: Optional[bool]
    note: Optional[str] = None
    witnesses: Optional[List[str]] = None


def _revoked_root(leaves) -> str:
    if not isinstance(leaves, (list, tuple)):
        leaves = []
    uniq = sorted({str(x).lower() for x in leaves})
    return hashlib.sha3_256("\n".join(uniq).encode("utf-8")).hexdigest()


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


def verify_id_token(tok: dict, audience=None, nonce=None, now=None) -> IdTokenVerdict:
    """Verify a polaris-id-token/1 (P8.4) as a relying party, offline: the issuing agency's
    signature, that it was issued to THIS audience, that it carries the login's nonce, and
    freshness (iat <= now < exp). The subject is a credential hash, never a person."""
    tok = tok if isinstance(tok, dict) else {}
    if tok.get("format") != "polaris-id-token/1":
        return IdTokenVerdict(False, None, None, None, tok.get("sub"), tok.get("acr"), "not a polaris-id-token/1")
    base = verify_signed_artifact(tok, now)
    if not base.authentic:
        return IdTokenVerdict(False, None, None, None, tok.get("sub"), tok.get("acr"), base.note)
    ia, ea = _iso_to_epoch(tok.get("iat")), _iso_to_epoch(tok.get("exp"))
    n = _iso_to_epoch(now) if now is not None else time.time()
    fresh = (ia <= n < ea) if (ia is not None and ea is not None and n is not None) else None
    return IdTokenVerdict(True, (tok.get("aud") == audience) if audience is not None else None,
                          (tok.get("nonce") == nonce) if nonce is not None else None, fresh,
                          tok.get("sub"), tok.get("acr"))


def verify_signed_artifact(obj: dict, now=None) -> ArtifactVerdict:
    """Verify a Polaris signed artifact's AUTHENTICITY offline (P8.1, wire spec section 3): for
    the epoch checkpoint, revocation feed, federation manifest, status bundle, or transparency
    STH, recompute the canonical statement for its `format`, verify the ML-DSA-65 signature over
    its SHA3-256, check freshness for a windowed artifact, and check the artifact's commitment
    (feed/bundle) or self-consistency (manifest). Standalone. Reports authentic + fresh. The
    federation TRUST decision (accepting a foreign credential across authorities) is a separate,
    composite check, not this per-artifact authenticity."""
    obj = obj if isinstance(obj, dict) else {}
    fmt = obj.get("format")
    keys = _ARTIFACT_KEYS.get(fmt)
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
        ok = _revoked_root(obj.get("revoked_leaves")) == str(obj.get("revoked_root_hex") or "").lower()
        note = None if ok else "the revocation feed's commitment does not match its leaves"
    elif ok and fmt == "polaris-epoch-leaves/1":
        # P9.2: the leaves ride outside the signed statement, committed to by leaves_root_hex,
        # so a verifier checks the set with SHA3-256 alone and never needs the proving library.
        leaves = obj.get("all_leaves_hex") if isinstance(obj.get("all_leaves_hex"), list) else []
        ok = (_revoked_root(leaves) == str(obj.get("leaves_root_hex") or "").lower()
              and len(leaves) == obj.get("leaf_count"))
        note = None if ok else "the published leaves do not match the committed set"
    elif ok and fmt == "polaris-federation-status-bundle/1":
        ok = _members_root(obj.get("members")) == str(obj.get("members_root_hex") or "").lower()
        note = None if ok else "the status bundle's members_root does not match its members"
    elif ok and fmt == "polaris-federation-manifest/1":
        active = {str(a.get("public_key_hex", "")).lower() for a in (obj.get("anchors") or [])
                  if isinstance(a, dict) and (a.get("status") or "active") == "active"}
        ok = str(obj.get("public_key_hex") or "").lower() in active
        note = None if ok else "the manifest is not signed by one of its own active anchors"
    elif ok and fmt == "polaris-registry/1":
        pub = obj.get("publisher") if isinstance(obj.get("publisher"), dict) else {}
        listed = [str(a.get("public_key_hex") or "").lower() for a in (obj.get("authorities") or [])
                  if isinstance(a, dict) and a.get("agency_id") == pub.get("agency_id")
                  and (a.get("status") or "active") == "active"]
        ok = str(obj.get("public_key_hex") or "").lower() in listed
        note = None if ok else "the registry is not signed by the key it lists for its own publisher"
    elif ok and fmt == "polaris-trust-list/1":
        pub = obj.get("publisher") if isinstance(obj.get("publisher"), dict) else {}
        active = [str(k.get("public_key_hex") or "").lower() for k in (obj.get("keys") or [])
                  if isinstance(k, dict) and k.get("agency_id") == pub.get("agency_id") and k.get("status") == "active"]
        ok = str(obj.get("public_key_hex") or "").lower() in active
        note = None if ok else "the trust list is not signed by a key it lists as active for its own publisher"
    return ArtifactVerdict(ok, _within_window(obj, now), note, ran)


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
        idx, tree_size = int(idx), int(tree_size)
    except (TypeError, ValueError):
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
    if ok and witness_key is not None and str(c.get("public_key_hex") or "").lower() != str(witness_key).lower():
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
    if str(proof.get("entry_hex") or "").lower() != v.timestamp_hash:
        v.note = "the proof is not for this timestamp"
        return v
    sv = verify_signed_artifact(sth)
    v.sth_authentic = bool(sv.authentic)
    if sth.get("log_id") != _TIMESTAMP_LOG_ID or proof.get("log_id") not in (None, _TIMESTAMP_LOG_ID):
        v.note = "the head is not a %s head" % _TIMESTAMP_LOG_ID
        return v
    try:
        idx, size = int(proof.get("index")), int(proof.get("tree_size"))
        root = bytes.fromhex(str(sth.get("root_hash_hex")))
        path = [bytes.fromhex(str(x)) for x in (proof.get("proof_hex") or [])]
    except (TypeError, ValueError):
        v.note = "malformed proof"
        return v
    v.index, v.tree_size = idx, size
    if size != sth.get("tree_size") or \
            str(proof.get("root_hash_hex") or "").lower() != str(sth.get("root_hash_hex") or "").lower():
        v.note = "the proof and the head describe different trees"
        return v
    if not v.sth_authentic:
        v.note = sv.note or "the head is not authentic"
        return v
    if log_key is not None and str(sth.get("public_key_hex") or "").lower() != str(log_key).lower():
        v.note = "the head is not signed by the expected log key"
        return v
    v.anchored = verify_inclusion(idx, size, _leaf_hash(v.timestamp_hash), root, path)
    if not v.anchored:
        v.note = "the inclusion proof does not reconstruct the head"
        return v
    if trusted_witnesses is not None:
        trusted = {str(t).lower() for t in trusted_witnesses}
        seen = set()
        for c in (anchor.get("cosignatures") or []):
            if not isinstance(c, dict) or not verify_cosignature(c).authentic:
                continue
            if (c.get("log_id") == sth.get("log_id") and c.get("tree_size") == sth.get("tree_size")
                    and str(c.get("root_hash_hex") or "").lower() == str(sth.get("root_hash_hex") or "").lower()):
                w = str(c.get("public_key_hex") or "").lower()
                if w in trusted:
                    seen.add(w)
        v.cosigner_count = len(seen)
        v.witnessed = v.cosigner_count >= int(threshold or 1)
        if not v.witnessed:
            v.note = "only %d trusted witness cosignature(s) over this head, need %d" % (v.cosigner_count, threshold)
    return v


@dataclasses.dataclass
class CrossAuthorityVerdict:
    decision: str                    # "accept" | "reject"
    authentic: bool
    issuer_trusted: bool
    via: Optional[str] = None
    reason: Optional[str] = None


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


def verify_holder(credential: dict, binding: dict, proof: dict, expected_nonce=None,
                  expected_context=None, now=None, max_age_seconds: int = 300) -> HolderVerdict:
    """Decide the holder key chain offline (P9.1): issuer anchor -> binding -> holder key -> proof.

    Polaris was issuer-centric until v9.349: a holder held a credential, not a key pair, so
    presenting the file was the whole of the proof. A holder proof answers a different
    question, whether the party presenting it holds the key the ISSUER bound to that
    credential. The proof is signed over the credential, the context, the verifier's nonce
    and the instant, and deliberately NOT over the presented code, so a coerced presentation
    stays byte-indistinguishable from a consenting one."""
    v = HolderVerdict(False, None, None, None, None, None, None)
    b = binding if isinstance(binding, dict) else {}
    pr = proof if isinstance(proof, dict) else {}
    if b.get("format") != "polaris-holder-binding/1" or pr.get("format") != "polaris-holder-proof/1":
        v.note = "a holder chain needs a polaris-holder-binding/1 and a polaris-holder-proof/1"
        return v
    bv = verify_signed_artifact(b, now=now)
    v.binding_authentic, v.binding_fresh = bv.authentic, bv.fresh
    cred = credential if isinstance(credential, dict) else {}
    v.bound_to_credential = (str(b.get("token_value")) == str(cred.get("token_value"))
                             and str(b.get("public_key_hex") or "").lower()
                             == str(cred.get("public_key_hex") or "").lower())
    keys = _ARTIFACT_KEYS["polaris-holder-proof/1"]
    ok, ran, note = _verify_over_digest(hashlib.sha3_256(_canonical(pr, keys)).digest(),
                                        pr.get("signature_hex"), pr.get("public_key_hex"), pr.get("algorithm"))
    v.proof_authentic = None if ok is None else bool(ok)
    v.key_matches_binding = (str(pr.get("public_key_hex") or "").lower()
                             == str(b.get("holder_public_key_hex") or "").lower()
                             and (b.get("status") or "active") == "active")
    if expected_nonce is not None:
        v.nonce_matches = (str(pr.get("verifier_nonce")) == str(expected_nonce))
    ctx_ok = expected_context is None or pr.get("context_id") == expected_context
    issued = _iso_to_epoch(pr.get("issued_at"))
    ref = _iso_to_epoch(now) if now else __import__("time").time()
    fresh = issued is not None and ref is not None and issued <= ref + 60 and (ref - issued) <= max_age_seconds
    v.proved = bool(v.binding_authentic and v.binding_fresh and v.bound_to_credential
                    and v.proof_authentic and v.key_matches_binding
                    and v.nonce_matches is not False and ctx_ok and fresh)
    if not v.proved:
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
    if ok and attesting_agency_id is not None and a.get("attesting_agency_id") != attesting_agency_id:
        return ArtifactVerdict(False, None, "the attestation names a different attesting agency "
                                            "than the manifest that published it", ran)
    if ok and expected_key is not None and \
            str(a.get("attested_public_key_hex") or "").lower() != str(expected_key).lower():
        return ArtifactVerdict(False, None, "the attestation is signed over a different attested key", ran)
    return ArtifactVerdict(bool(ok), None, None if ok else "the attestation signature is invalid", ran)


def verify_cross_authority(pack: dict, context_id, manifests, trusted_anchors=None,
                           revocation_feed=None, now=None,
                           require_signed_attestation: bool = False) -> CrossAuthorityVerdict:
    """Decide a FOREIGN credential across authorities OFFLINE (P8.1, wire spec section 4).
    Accept iff: the authenticity pack is genuine; some federation manifest the relying party
    trusts (authentic, fresh, and signed by a trusted anchor) attests the credential's signing
    key in the presented context, non-transitively; and, if a revocation feed is supplied, the
    credential is not revoked (the feed authentic, fresh, and bound to the issuer's key).
    Standalone, no network."""
    pack = pack if isinstance(pack, dict) else {}
    a = verify_authenticity(pack)
    if not a.authentic:
        return CrossAuthorityVerdict("reject", False, False, reason="credential is not authentic")
    token_key = str(pack.get("public_key_hex") or "").lower()
    trusted = {t.lower() for t in trusted_anchors} if trusted_anchors is not None else None
    via = None
    signed_edge = None
    for m in (manifests or []):
        m = m if isinstance(m, dict) else {}
        mv = verify_signed_artifact(m, now=now)   # manifest: signature + self-consistency + freshness
        if not (mv.authentic and mv.fresh):
            continue
        active = {str(x.get("public_key_hex", "")).lower() for x in (m.get("anchors") or [])
                  if isinstance(x, dict) and (x.get("status") or "active") == "active"}
        if trusted is not None and not (active & trusted):
            continue   # the relying party does not trust this manifest's authority
        for att in (m.get("attestations") or []):
            if not isinstance(att, dict):
                continue
            if (str(att.get("attested_public_key_hex") or "").lower() == token_key
                    and (context_id is None or att.get("context_id") == context_id)):
                # P9.5: is the edge signed by the agency that made it, or is it the
                # operator's word carried by the manifest's signature?
                auth = m.get("authority") if isinstance(m.get("authority"), dict) else {}
                av = verify_attestation(att, attesting_agency_id=auth.get("agency_id"), expected_key=token_key)
                unsigned = not att.get("signature_hex") and not att.get("public_key_hex")
                if not unsigned and not av.authentic:
                    continue    # a present-but-bad signature is worse than none: refuse the edge
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
    if revocation_feed is not None:
        rv = verify_signed_artifact(revocation_feed if isinstance(revocation_feed, dict) else {}, now=now)
        bound = str((revocation_feed or {}).get("public_key_hex") or "").lower() == token_key
        if not (rv.authentic and rv.fresh and bound):
            return CrossAuthorityVerdict("reject", True, True, via if isinstance(via, str) else None,
                                         "the issuer's revocation feed is not authentic, fresh, and bound to the issuer key")
        leaf = hashlib.sha3_256(str(pack.get("token_value") or "").encode("utf-8")).hexdigest()
        if leaf in {str(x).lower() for x in (revocation_feed.get("revoked_leaves") or [])}:
            return CrossAuthorityVerdict("reject", True, True, via if isinstance(via, str) else None,
                                         "credential is revoked in the issuer's published feed")
    return CrossAuthorityVerdict("accept", True, True, via if isinstance(via, str) else None)


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

    # --- OAuth2 client-credentials (cached, refreshed on expiry) --------------
    def _access_token(self):
        if self._bearer and time.time() < self._bearer_exp - 5:
            return self._bearer
        creds = base64.b64encode(("%s:%s" % (self.client_id, self.client_secret)).encode()).decode()
        req = urllib.request.Request(
            "%s/api/v1/oauth/token" % self.issuer_url, data=b"grant_type=client_credentials",
            headers={"Authorization": "Basic " + creds,
                     "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            body = json.loads(r.read())
        self._bearer = body["access_token"]
        self._bearer_exp = time.time() + int(body.get("expires_in", 300))
        return self._bearer

    def _online_status(self, cred):
        body = json.dumps({"token_value": cred.get("token_value"),
                           "signature_hex": cred.get("signature_hex")}).encode()
        req = urllib.request.Request(
            "%s/api/v1/verify" % self.issuer_url, data=body,
            headers={"Authorization": "Bearer " + self._access_token(),
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
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
        current = bool(status.get("currently_authoritative"))
        if not current:
            reasons.append("not currently authoritative (revoked/inactive): status=%s" % status.get("status"))
        return Verdict("accept" if current else "reject", True, a.issuer_trusted, current,
                       status=status.get("status"), reasons=reasons or None)
