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
ALGORITHM = "ML-DSA-65"
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


def _verify_cryptography(digest, sig, pk):
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return None
    if not hasattr(mldsa, "MLDSA65PublicKey"):
        return None
    try:
        key = mldsa.MLDSA65PublicKey.from_public_bytes(pk)
    except Exception:
        return None
    try:
        key.verify(sig, digest)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _verify_liboqs(digest, sig, pk):
    try:
        import oqs  # type: ignore
    except Exception:
        return None
    try:
        with oqs.Signature(ALGORITHM) as v:
            return bool(v.verify(digest, sig, pk))
    except Exception:
        return False


def verify_authenticity(pack: dict, anchors=None) -> AuthenticityVerdict:
    """Verify a Polaris authenticity pack OFFLINE. `anchors` is an optional
    iterable of trusted issuer public keys (hex); when given, issuer_trusted says
    whether the pack's key is one of them."""
    tok = pack.get("token_value")
    alg = pack.get("algorithm")
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
    primary = _verify_cryptography(digest, sig, pk)
    witness = _verify_liboqs(digest, sig, pk)
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


def _verify_over_digest(digest, sig_hex, pk_hex):
    """Dual-witness ML-DSA-65 verify over a digest. Returns (ok, witnesses, note); ok is
    None when no verifier is available or the witnesses disagree."""
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        return None, [], "signature_hex/public_key_hex are not valid hex"
    primary = _verify_cryptography(digest, sig, pk)
    witness = _verify_liboqs(digest, sig, pk)
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
    ok, ran, note = _verify_over_digest(digest, assertion.get("signature_hex"), assertion.get("public_key_hex"))
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
                                        obj.get("signature_hex"), obj.get("public_key_hex"))
    if ok is None:
        return ArtifactVerdict(False, None, note, ran)
    ok = bool(ok)
    if ok and fmt == "polaris-revocation-feed/1":
        ok = _revoked_root(obj.get("revoked_leaves")) == str(obj.get("revoked_root_hex") or "").lower()
        note = None if ok else "the revocation feed's commitment does not match its leaves"
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
    return ArtifactVerdict(ok, _within_window(obj, now), note, ran)


@dataclasses.dataclass
class CrossAuthorityVerdict:
    decision: str                    # "accept" | "reject"
    authentic: bool
    issuer_trusted: bool
    via: Optional[str] = None
    reason: Optional[str] = None


def verify_cross_authority(pack: dict, context_id, manifests, trusted_anchors=None,
                           revocation_feed=None, now=None) -> CrossAuthorityVerdict:
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
