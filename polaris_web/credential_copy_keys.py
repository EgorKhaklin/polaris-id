# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/credential_copy_keys.py: the ES256 keys wallet copies are signed with.

A wallet copy (docs/design/oid4vci-issuer.md) is an SD-JWT VC signed ES256 under the issuing
agency's certificate, because the SD-JWT VC profile and every wallet the lab met require it.
It is a classical credential, and this module holds the only classical signing key in
polaris_web. It is separate from custody.py on purpose: the ML-DSA custody key never signs a
wallet copy, and this key signs nothing else; the certificate enforces the second half, since a
leaf that could sign certificates is refused.

Version 1 keeps the key as a file, per agency, in POLARIS_CREDENTIAL_COPY_KEYS_DIR:

    <agency_id>.key.pem     the leaf's private key, PKCS#8 PEM, EC P-256, mode 0600
    <agency_id>.chain.pem   the leaf certificate first, then any intermediates; the trust
                            anchor is left out, as HAIP asks, and relying parties register it

A key that fails any of these is refused rather than used, because a wallet copy signed under
a chain a verifier must reject is a copy nobody can use, and the operator should learn that
from the load, not from a holder:
  - the key file is not open to group or others;
  - the key is EC P-256 and is the leaf certificate's key;
  - the leaf is not a CA and does not carry keyCertSign; it does carry digitalSignature;
  - no certificate in the file is self-signed (the anchor stays out);
  - each certificate is issued by the next one, and every one after the leaf is a CA;
  - every certificate is inside its validity window, checked again each time the key is used.

PKCS#11 and KMS come later, through the custody interface (the design record says so).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import os
import re
import stat
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

KEYS_DIR_ENV = "POLARIS_CREDENTIAL_COPY_KEYS_DIR"
# Canonical decimal only, so one agency cannot be named by two file names ("7" and "007").
_AGENCY_ID_RE = re.compile(r"\A[1-9][0-9]{0,11}\Z")


class CopyKeyError(RuntimeError):
    """A wallet-copy key could not be used. `configured` is False when none was supplied at all,
    which the endpoints answer as "not offered here" rather than as a fault."""

    def __init__(self, message: str, configured: bool = True):
        super().__init__(message)
        self.configured = configured


def _iso(moment: datetime.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class CopyKey:
    agency_id: int
    private_key: "EllipticCurvePrivateKey"
    x5c: tuple                        # base64 DER, leaf first, anchor excluded
    leaf_fingerprint: str             # SHA-256 of the leaf DER, hex
    valid_from: datetime.datetime     # the latest not-before in the chain
    valid_until: datetime.datetime    # the earliest not-after in the chain
    san_uris: tuple
    san_dns: tuple

    def sign(self, signing_input: bytes) -> bytes:
        """ES256 over the JWS signing input: raw r||s, 64 bytes, as JWS wants it."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        der = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def names_issuer(self, issuer_url: str) -> bool:
        """Whether the leaf names this credential issuer: SD-JWT VC ties an x5c-signed
        credential's `iss` to a uniformResourceIdentifier in the leaf's subjectAltName."""
        return issuer_url in self.san_uris

    def credential_issuer(self, path: str):
        """The credential issuer identifier this leaf names for `path`: its one https URI
        subjectAltName whose path is exactly `path`. None when there is none, or more than one,
        because then the certificate does not say which issuer it is."""
        import urllib.parse
        found = []
        for uri in self.san_uris:
            parts = urllib.parse.urlsplit(uri)
            if parts.scheme == "https" and parts.hostname and parts.path == path \
                    and not parts.query and not parts.fragment:
                found.append(uri)
        return found[0] if len(found) == 1 else None

    def describe(self) -> dict:
        """Non-secret facts, for health and the operator."""
        return {"agency_id": self.agency_id, "leaf_sha256": self.leaf_fingerprint,
                "valid_until": _iso(self.valid_until), "chain_length": len(self.x5c),
                "names": list(self.san_uris)}


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _issued_by(cert, issuer) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:  # noqa: BLE001  any failure to verify is "not issued by"
        return False
    return True


def _extension(cert, cls) -> Any:
    from cryptography import x509
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def _read_key_file(agency_id, key_path: str) -> bytes:
    """Open first, then check the mode of what was opened, so the file checked is the file read."""
    try:
        fd = os.open(key_path, os.O_RDONLY)
    except OSError as exc:
        raise CopyKeyError("agency %s: cannot open the key file: %s" % (agency_id, exc)) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CopyKeyError("agency %s: the key file is not a regular file" % agency_id)
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise CopyKeyError("agency %s: the key file is open to group or others (mode %o); it "
                               "must be 0600" % (agency_id, mode))
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


def load_from_files(agency_id, key_path: str, chain_path: str, now=None) -> CopyKey:
    """Load and check one agency's key and chain. Raises CopyKeyError with the reason."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    now = now or _now()
    key_pem = _read_key_file(agency_id, key_path)
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
        with open(chain_path, "rb") as fh:
            chain = x509.load_pem_x509_certificates(fh.read())
    except (OSError, ValueError, TypeError) as exc:
        raise CopyKeyError("agency %s: the key or chain file is unreadable: %s"
                           % (agency_id, exc)) from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise CopyKeyError("agency %s: the key is not EC P-256, so it cannot sign ES256" % agency_id)
    leaf = chain[0]  # never empty: the loader raises ValueError on a file with no certificate

    def spki(public_key) -> bytes:
        return public_key.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)

    if spki(leaf.public_key()) != spki(key.public_key()):
        raise CopyKeyError("agency %s: the first certificate is not the key's; the leaf must "
                           "come first" % agency_id)

    constraints = _extension(leaf, x509.BasicConstraints)
    usage = _extension(leaf, x509.KeyUsage)
    if constraints is not None and constraints.ca:
        raise CopyKeyError("agency %s: the leaf is a CA certificate; the wallet-copy key must "
                           "not be able to issue certificates" % agency_id)
    if usage is None or not usage.digital_signature:
        raise CopyKeyError("agency %s: the leaf does not carry the digitalSignature key usage, "
                           "which verifiers require of a signing certificate" % agency_id)
    if usage.key_cert_sign:
        raise CopyKeyError("agency %s: the leaf carries keyCertSign; the wallet-copy key must "
                           "not be able to issue certificates" % agency_id)

    for i, cert in enumerate(chain):
        if cert.issuer == cert.subject and _issued_by(cert, cert):
            raise CopyKeyError("agency %s: certificate %d is self-signed; the leaf must not be, "
                               "and the trust anchor stays out of the chain (relying parties "
                               "register it)" % (agency_id, i))
        if i > 0:
            ca = _extension(cert, x509.BasicConstraints)
            if ca is None or not ca.ca:
                raise CopyKeyError("agency %s: certificate %d follows the leaf but is not a CA "
                                   "certificate" % (agency_id, i))
        if i + 1 < len(chain) and not _issued_by(cert, chain[i + 1]):
            raise CopyKeyError("agency %s: certificate %d is not issued by certificate %d"
                               % (agency_id, i, i + 1))

    valid_from = max(c.not_valid_before_utc for c in chain)
    valid_until = min(c.not_valid_after_utc for c in chain)
    _check_window(agency_id, valid_from, valid_until, now)

    san = _extension(leaf, x509.SubjectAlternativeName)
    der = [c.public_bytes(serialization.Encoding.DER) for c in chain]
    return CopyKey(
        agency_id=int(agency_id), private_key=key,
        x5c=tuple(base64.b64encode(d).decode("ascii") for d in der),
        leaf_fingerprint=hashlib.sha256(der[0]).hexdigest(),
        valid_from=valid_from, valid_until=valid_until,
        san_uris=tuple(san.get_values_for_type(x509.UniformResourceIdentifier)) if san else (),
        san_dns=tuple(san.get_values_for_type(x509.DNSName)) if san else ())


def _check_window(agency_id, valid_from, valid_until, now) -> None:
    if not (valid_from <= now <= valid_until):
        raise CopyKeyError("agency %s: the chain is valid only from %s to %s"
                           % (agency_id, _iso(valid_from), _iso(valid_until)))


_lock = threading.Lock()
_cache: dict = {}


def _stamp(path: str) -> tuple:
    st = os.stat(path)
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def key_for_agency(agency_id) -> CopyKey:
    """The agency's wallet-copy key from POLARIS_CREDENTIAL_COPY_KEYS_DIR, checked, cached, and
    reloaded when either file changes. Raises CopyKeyError; see its `configured`."""
    directory = os.environ.get(KEYS_DIR_ENV)
    if not directory:
        raise CopyKeyError("wallet copies are not configured on this instance (%s is unset)"
                           % KEYS_DIR_ENV, configured=False)
    name = str(agency_id)
    if isinstance(agency_id, bool) or not _AGENCY_ID_RE.match(name):
        raise CopyKeyError("not an agency id: %r" % (agency_id,), configured=False)
    key_path = os.path.join(directory, "%s.key.pem" % name)
    chain_path = os.path.join(directory, "%s.chain.pem" % name)
    try:
        stamp = (_stamp(key_path), _stamp(chain_path))
    except OSError:
        raise CopyKeyError("agency %s has no wallet-copy key on this instance" % name,
                           configured=False) from None
    with _lock:
        cached = _cache.get(name)
        if cached is None or cached[0] != stamp:
            _cache.pop(name, None)
            cached = (stamp, load_from_files(name, key_path, chain_path))
            _cache[name] = cached
    key = cached[1]
    _check_window(name, key.valid_from, key.valid_until, _now())
    return key


def reset() -> None:
    with _lock:
        _cache.clear()
