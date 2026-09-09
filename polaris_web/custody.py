"""polaris_web/custody.py — key custody abstraction for the issuer signing key
(roadmap P1.2).

Polaris has exactly one long-lived private key: the issuer's ML-DSA-65 (FIPS 204)
token-signing key. Epoch anchors are hash-chained, not signed, so nothing else
needs custody today; anything that does later goes through this interface.

Before this module the key was a JSON file the app read into memory. That is
the `file` driver here, kept for development and small deployments. Two more
drivers put the private key where a national authority keeps it:

  file    {algorithm, secret_key_hex, public_key_hex} JSON (0600), signed via
          liboqs in-process. POLARIS_PQC_SIGNING_KEY_FILE.
  pkcs11  a PKCS#11 v3.2 token (HSM, or a software token such as Kryoptic):
          the key is generated IN the token, non-extractable, and every
          signature is CKM_ML_DSA inside it. POLARIS_CUSTODY_PKCS11_*.
  awskms  an AWS KMS asymmetric key of KeySpec ML_DSA_65: Sign with
          ML_DSA_SHAKE_256; the private key never leaves KMS's HSMs.
          POLARIS_CUSTODY_AWSKMS_*.

The contract every driver meets is small: `public_key()` returns the raw
1952-byte ML-DSA-65 public key and `sign(digest)` returns the raw 3309-byte
pure-ML-DSA-65 signature over the 32-byte SHA3-256 digest Polaris signs. That
keeps the verification path (`pqc_signing.verify_both`: liboqs AND an
independent OpenSSL implementation must agree) byte-for-byte unchanged: a
verifier cannot tell which driver produced a signature, and every signature
any driver produces is checked by both witnesses before it is stored.

Secrets never travel through env: the PKCS#11 PIN is read from a file
(POLARIS_CUSTODY_PKCS11_PIN_FILE) and the module refuses to start if
POLARIS_CUSTODY_PKCS11_PIN is set; KMS credentials are the SDK's usual
instance-role / profile chain. The driver's `describe()` exposes only
non-secret facts (driver, key id, public-key fingerprint) for /api/health and
polaris-pqc-status.sh.

Key ceremony and rotation: docs/operator/KEY-CEREMONY.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from typing import Optional

# P8.8a (v9.329): the accepted FIPS 204 parameter sets and their raw sizes. ML-DSA-65 (NIST
# level 3) is the default; ML-DSA-87 (level 5) is accepted for migration and high-assurance
# keys; ML-DSA-44 is below the system's floor and is not accepted anywhere. A key file names
# its parameter set and the driver signs under it, so one instance can hold keys of both.
DEFAULT_ALGORITHM = "ML-DSA-65"
ALGORITHM_SIZES = {"ML-DSA-65": (1952, 3309), "ML-DSA-87": (2592, 4627)}
ACCEPTED_ALGORITHMS = tuple(ALGORITHM_SIZES)
ALGORITHM = DEFAULT_ALGORITHM          # the historical name of the default parameter set
PUBLIC_KEY_LEN, SIGNATURE_LEN = ALGORITHM_SIZES[DEFAULT_ALGORITHM]
DIGEST_LEN = 32
_ALGORITHM_ENV = "POLARIS_PQC_ALGORITHM"


def configured_algorithm() -> str:
    """The parameter set this process generates keys and ephemeral signatures under:
    POLARIS_PQC_ALGORITHM, default ML-DSA-65. An unaccepted value fails loud."""
    alg = os.environ.get(_ALGORITHM_ENV) or DEFAULT_ALGORITHM
    if alg not in ALGORITHM_SIZES:
        raise CustodyError(f"{_ALGORITHM_ENV}={alg!r} is not an accepted algorithm "
                           f"({', '.join(ACCEPTED_ALGORITHMS)})")
    return alg


def algorithm_for_public_key(public_key: bytes):
    """The accepted parameter set a raw public key's length identifies, or None."""
    for name, (pk_len, _sig_len) in ALGORITHM_SIZES.items():
        if len(public_key) == pk_len:
            return name
    return None

# ML-DSA-65 SubjectPublicKeyInfo: the raw key is the BIT STRING payload after a
# fixed 22-byte header (SEQUENCE, AlgorithmIdentifier OID 2.16.840.1.101.3.4.3.18,
# BIT STRING with 0 unused bits). Used only as a fallback when cryptography
# cannot parse the SPKI itself.
_SPKI_HEADER_LEN = 22

_DRIVER_ENV = "POLARIS_CUSTODY_DRIVER"


class CustodyError(RuntimeError):
    """The custody backend is misconfigured, unreachable, or returned material of
    the wrong shape. Always fatal on the signing path: a signature that cannot be
    produced by the custodied key must never degrade to an ephemeral one."""


def fingerprint(public_key: bytes) -> str:
    """Short, stable identifier of a public key: sha3-256, first 16 hex chars."""
    return hashlib.sha3_256(public_key).hexdigest()[:16]


class KeyCustody:
    """The interface. Drivers subclass and implement public_key() and sign()."""

    driver = "abstract"
    algorithm = DEFAULT_ALGORITHM   # the parameter set of the custodied key

    @property
    def key_id(self) -> str:
        raise NotImplementedError

    def public_key(self) -> bytes:
        raise NotImplementedError

    def sign(self, digest: bytes) -> bytes:
        raise NotImplementedError

    # ---- shared plumbing -------------------------------------------------
    def _check_digest(self, digest: bytes) -> None:
        if not isinstance(digest, (bytes, bytearray)) or len(digest) != DIGEST_LEN:
            raise CustodyError(f"{self.driver}: sign() takes the {DIGEST_LEN}-byte SHA3-256 digest, "
                               f"got {len(digest) if isinstance(digest, (bytes, bytearray)) else type(digest)}")

    def _check_public_key(self, pk: bytes) -> bytes:
        if len(pk) != ALGORITHM_SIZES[self.algorithm][0]:
            raise CustodyError(f"{self.driver}: public key is {len(pk)} bytes, not the {ALGORITHM_SIZES[self.algorithm][0]} of "
                               f"{self.algorithm} (wrong key type or parameter set?)")
        return bytes(pk)

    def _check_signature(self, sig: bytes) -> bytes:
        if len(sig) != ALGORITHM_SIZES[self.algorithm][1]:
            raise CustodyError(f"{self.driver}: signature is {len(sig)} bytes, not the {ALGORITHM_SIZES[self.algorithm][1]} of "
                               f"{self.algorithm}")
        return bytes(sig)

    def describe(self) -> dict:
        """Non-secret facts for health/status surfaces. No paths, no PINs."""
        pk = self.public_key()
        return {
            "driver": self.driver,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_fingerprint": fingerprint(pk),
            "public_key_len": len(pk),
        }


# ---------------------------------------------------------------------------
# file
# ---------------------------------------------------------------------------
class FileCustody(KeyCustody):
    """The JSON key file (development and small deployments). The secret key is
    in process memory; that is the trade-off this driver makes explicit."""

    driver = "file"

    def __init__(self, path: str):
        self._path = path
        try:
            with open(path) as fh:
                data = json.load(fh)
            if data.get("algorithm") not in ALGORITHM_SIZES:
                raise CustodyError(f"file: {path} algorithm {data.get('algorithm')!r} is not accepted "
                                   f"({', '.join(ACCEPTED_ALGORITHMS)})")
            self.algorithm = data["algorithm"]
            self._sk = bytes.fromhex(data["secret_key_hex"])
            self._pk = self._check_public_key(bytes.fromhex(data["public_key_hex"]))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CustodyError(f"file: {path} is unreadable/malformed: {exc}") from exc

    @property
    def key_id(self) -> str:
        return f"file:{fingerprint(self._pk)}"

    def public_key(self) -> bytes:
        return self._pk

    def sign(self, digest: bytes) -> bytes:
        self._check_digest(digest)
        try:
            import oqs  # type: ignore
        except ImportError as exc:
            raise CustodyError(f"file: liboqs-python is required to sign with a file key: {exc}") from exc
        with oqs.Signature(self.algorithm, secret_key=self._sk) as signer:
            return self._check_signature(signer.sign(bytes(digest)))

    def keypair(self) -> tuple:
        """(secret_key, public_key): the file driver is the only one that HAS the
        secret; pqc_signing's legacy loader reads it through here."""
        return self._sk, self._pk


# ---------------------------------------------------------------------------
# pkcs11
# ---------------------------------------------------------------------------
class Pkcs11Custody(KeyCustody):
    """A PKCS#11 v3.2 token holding a non-extractable ML-DSA-65 key found by
    label. Signing is CKM_ML_DSA inside the token; the private key is never
    read. One short session per operation (simple and thread-safe under a
    lock); the public key is cached after the first read."""

    driver = "pkcs11"

    def __init__(self, module: str, token_label: str, pin: str, key_label: str = "polaris-issuer"):
        self._module = module
        self._token_label = token_label
        self._pin = pin
        self._key_label = key_label
        self._lock = threading.Lock()
        self._pk: Optional[bytes] = None
        try:
            import pkcs11  # type: ignore
        except ImportError as exc:
            raise CustodyError("pkcs11: the python-pkcs11 package is required "
                               f"(pip install -r polaris_web/requirements-custody.txt): {exc}") from exc
        self._pkcs11 = pkcs11
        try:
            self._lib = pkcs11.lib(module)
            self._token = self._lib.get_token(token_label=token_label)
        except Exception as exc:
            raise CustodyError(f"pkcs11: cannot open module/token ({module!r}, label {token_label!r}): {exc}") from exc

    @property
    def key_id(self) -> str:
        return f"pkcs11:{self._token_label}/{self._key_label}"

    def public_key(self) -> bytes:
        with self._lock:
            if self._pk is None:
                p = self._pkcs11
                try:
                    with self._token.open(user_pin=self._pin) as s:
                        pub = s.get_key(object_class=p.ObjectClass.PUBLIC_KEY, label=self._key_label)
                        self._pk = self._check_public_key(bytes(pub[p.Attribute.VALUE]))
                except CustodyError:
                    raise
                except Exception as exc:
                    raise CustodyError(f"pkcs11: no public key labelled {self._key_label!r} readable in token "
                                       f"{self._token_label!r}: {exc}") from exc
            return self._pk

    def sign(self, digest: bytes) -> bytes:
        self._check_digest(digest)
        p = self._pkcs11
        with self._lock:
            try:
                with self._token.open(user_pin=self._pin) as s:
                    priv = s.get_key(object_class=p.ObjectClass.PRIVATE_KEY, label=self._key_label)
                    sig = priv.sign(bytes(digest), mechanism=p.Mechanism.ML_DSA)
            except Exception as exc:
                raise CustodyError(f"pkcs11: CKM_ML_DSA sign with {self._key_label!r} failed: {exc}") from exc
        return self._check_signature(bytes(sig))


def pkcs11_generate_key(module: str, token_label: str, pin: str, key_label: str = "polaris-issuer") -> bytes:
    """The PKCS#11 half of the key ceremony: generate an ML-DSA-65 keypair INSIDE
    the token (CKM_ML_DSA_KEY_PAIR_GEN, parameter set ML-DSA-65), private key
    sensitive and non-extractable, both halves persistent and labelled. Returns
    the raw public key (publish it as the trust anchor). Refuses if a key with
    that label already exists: rotation uses a new label."""
    import pkcs11  # type: ignore
    from pkcs11.mechanisms import MLDSAParameterSet  # type: ignore
    lib = pkcs11.lib(module)
    token = lib.get_token(token_label=token_label)
    with token.open(rw=True, user_pin=pin) as s:
        existing = list(s.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                                       pkcs11.Attribute.LABEL: key_label}))
        if existing:
            raise CustodyError(f"pkcs11: a private key labelled {key_label!r} already exists; "
                               "rotate with a NEW label, never overwrite")
        pub, _priv = s.generate_keypair(
            pkcs11.KeyType.ML_DSA, mechanism=pkcs11.Mechanism.ML_DSA_KEY_PAIR_GEN, store=True,
            public_template={pkcs11.Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_65,
                             pkcs11.Attribute.TOKEN: True, pkcs11.Attribute.LABEL: key_label},
            private_template={pkcs11.Attribute.TOKEN: True, pkcs11.Attribute.LABEL: key_label,
                              pkcs11.Attribute.SENSITIVE: True, pkcs11.Attribute.EXTRACTABLE: False,
                              pkcs11.Attribute.SIGN: True})
        pk = bytes(pub[pkcs11.Attribute.VALUE])
    if len(pk) != PUBLIC_KEY_LEN:
        raise CustodyError(f"pkcs11: generated public key is {len(pk)} bytes, not {PUBLIC_KEY_LEN}")
    return pk


# ---------------------------------------------------------------------------
# awskms
# ---------------------------------------------------------------------------
_KMS_KEY_SPEC = "ML_DSA_65"
_KMS_SIGNING_ALGORITHM = "ML_DSA_SHAKE_256"   # pure ML-DSA over the raw message


def _spki_to_raw(der: bytes) -> bytes:
    """Raw ML-DSA-65 public key out of a DER SubjectPublicKeyInfo."""
    try:
        from cryptography.hazmat.primitives import serialization  # type: ignore
        key = serialization.load_der_public_key(der)
        return key.public_bytes_raw()  # type: ignore[attr-defined]
    except Exception:
        if len(der) == _SPKI_HEADER_LEN + PUBLIC_KEY_LEN:
            return der[_SPKI_HEADER_LEN:]
        raise


class AwsKmsCustody(KeyCustody):
    """An AWS KMS asymmetric key (KeySpec ML_DSA_65, KeyUsage SIGN_VERIFY). The
    private key lives in KMS's HSMs; Polaris calls Sign with MessageType RAW and
    SigningAlgorithm ML_DSA_SHAKE_256 over the SHA3-256 digest, which is the same
    pure-ML-DSA operation the file and PKCS#11 drivers perform."""

    driver = "awskms"

    def __init__(self, key_id: str, region: Optional[str] = None, endpoint_url: Optional[str] = None):
        self._key_id = key_id
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise CustodyError("awskms: the boto3 package is required "
                               f"(pip install -r polaris_web/requirements-custody.txt): {exc}") from exc
        kw = {}
        if region:
            kw["region_name"] = region
        if endpoint_url:
            kw["endpoint_url"] = endpoint_url
        self._kms = boto3.client("kms", **kw)
        try:
            meta = self._kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except Exception as exc:
            raise CustodyError(f"awskms: DescribeKey {key_id!r} failed: {exc}") from exc
        spec = meta.get("KeySpec")
        if spec != _KMS_KEY_SPEC or meta.get("KeyUsage") != "SIGN_VERIFY":
            raise CustodyError(f"awskms: key {key_id!r} is KeySpec={spec} KeyUsage={meta.get('KeyUsage')}; "
                               f"need {_KMS_KEY_SPEC} / SIGN_VERIFY")
        if meta.get("KeyState") not in (None, "Enabled"):
            raise CustodyError(f"awskms: key {key_id!r} is {meta.get('KeyState')}, not Enabled")
        self._arn = meta.get("Arn", key_id)
        try:
            der = self._kms.get_public_key(KeyId=key_id)["PublicKey"]
            self._pk = self._check_public_key(_spki_to_raw(bytes(der)))
        except CustodyError:
            raise
        except Exception as exc:
            raise CustodyError(f"awskms: GetPublicKey {key_id!r} failed or is not an {ALGORITHM} SPKI: {exc}") from exc

    @property
    def key_id(self) -> str:
        return f"awskms:{self._arn}"

    def public_key(self) -> bytes:
        return self._pk

    def sign(self, digest: bytes) -> bytes:
        self._check_digest(digest)
        try:
            out = self._kms.sign(KeyId=self._key_id, Message=bytes(digest), MessageType="RAW",
                                 SigningAlgorithm=_KMS_SIGNING_ALGORITHM)
        except Exception as exc:
            raise CustodyError(f"awskms: Sign with {self._key_id!r} failed: {exc}") from exc
        return self._check_signature(bytes(out["Signature"]))


# ---------------------------------------------------------------------------
# selection from env, cached per configuration
# ---------------------------------------------------------------------------
def _read_secret_file(path: str, what: str) -> str:
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError as exc:
        raise CustodyError(f"{what}: cannot read {path}: {exc}") from exc


def _config_from_env() -> tuple:
    driver = os.environ.get(_DRIVER_ENV, "").strip().lower()
    if not driver:
        driver = "file" if os.environ.get("POLARIS_PQC_SIGNING_KEY_FILE") else ""
    if driver == "":
        return ("",)
    if driver == "file":
        return ("file", os.environ.get("POLARIS_PQC_SIGNING_KEY_FILE", ""))
    if driver == "pkcs11":
        if os.environ.get("POLARIS_CUSTODY_PKCS11_PIN"):
            raise CustodyError("pkcs11: POLARIS_CUSTODY_PKCS11_PIN is set; the PIN must come from "
                               "POLARIS_CUSTODY_PKCS11_PIN_FILE (env leaks via docker inspect and ps)")
        return ("pkcs11",
                os.environ.get("POLARIS_CUSTODY_PKCS11_MODULE", ""),
                os.environ.get("POLARIS_CUSTODY_PKCS11_TOKEN_LABEL", "polaris"),
                os.environ.get("POLARIS_CUSTODY_PKCS11_PIN_FILE", ""),
                os.environ.get("POLARIS_CUSTODY_PKCS11_KEY_LABEL", "polaris-issuer"))
    if driver == "awskms":
        return ("awskms",
                os.environ.get("POLARIS_CUSTODY_AWSKMS_KEY_ID", ""),
                os.environ.get("POLARIS_CUSTODY_AWSKMS_REGION", ""),
                os.environ.get("POLARIS_CUSTODY_AWSKMS_ENDPOINT_URL", ""))
    raise CustodyError(f"{_DRIVER_ENV}={driver!r} is not one of file, pkcs11, awskms")


def from_env() -> Optional[KeyCustody]:
    """Build the custody driver the environment selects; None when no persistent
    key is configured (the dev/test ephemeral fallback in pqc_signing)."""
    cfg = _config_from_env()
    if cfg[0] == "":
        return None
    if cfg[0] == "file":
        if not cfg[1]:
            raise CustodyError("file: POLARIS_PQC_SIGNING_KEY_FILE is required")
        return FileCustody(cfg[1])
    if cfg[0] == "pkcs11":
        _, module, token_label, pin_file, key_label = cfg
        if not module or not pin_file:
            raise CustodyError("pkcs11: POLARIS_CUSTODY_PKCS11_MODULE and POLARIS_CUSTODY_PKCS11_PIN_FILE are required")
        return Pkcs11Custody(module, token_label, _read_secret_file(pin_file, "pkcs11 PIN"), key_label)
    _, key_id, region, endpoint = cfg
    if not key_id:
        raise CustodyError("awskms: POLARIS_CUSTODY_AWSKMS_KEY_ID is required")
    return AwsKmsCustody(key_id, region or None, endpoint or None)


_lock = threading.Lock()
_current: Optional[KeyCustody] = None
_current_cfg: Optional[tuple] = None


def get_custody() -> Optional[KeyCustody]:
    """The process's custody driver, built once per configuration (a changed env
    rebuilds it, which is what tests rely on). Raises CustodyError loudly on a
    misconfiguration; never falls back."""
    global _current, _current_cfg
    cfg = _config_from_env()
    with _lock:
        if _current_cfg != cfg:
            _current = from_env()
            _current_cfg = cfg
        return _current


# PE.3b (v9.286) — per-agency signing keys for federation in the running app.
# POLARIS_AGENCY_KEYS_DIR, when set, is a directory of ML-DSA-65 key files named
# "<agency_id>.json" (the same shape the file driver reads). Issuance asks for the
# issuing agency's key; if the directory or that agency's file is absent, it falls
# back to the single global custody key — so single-key deployments are unchanged.
_AGENCY_KEYS_DIR_ENV = "POLARIS_AGENCY_KEYS_DIR"
_AGENCY_ID_RE = re.compile(r"\A[0-9]{1,12}\Z")
_agency_custody: dict = {}


def get_custody_for_agency(agency_id) -> Optional[KeyCustody]:
    """The custody driver that signs for a specific issuing agency: its own key
    when POLARIS_AGENCY_KEYS_DIR holds "<agency_id>.json", else the global key.
    A per-agency file that is present but malformed fails loud (CustodyError);
    an absent one is a silent, deliberate fallback to the global key."""
    d = os.environ.get(_AGENCY_KEYS_DIR_ENV)
    if not d or agency_id is None or not _AGENCY_ID_RE.match(str(agency_id)):
        return get_custody()
    path = os.path.join(d, "%s.json" % agency_id)
    if not os.path.isfile(path):
        return get_custody()
    with _lock:
        cached = _agency_custody.get(path)
        if cached is None or cached[0] != os.path.getmtime(path):
            _agency_custody[path] = (os.path.getmtime(path), FileCustody(path))
        return _agency_custody[path][1]


def reset() -> None:
    global _current, _current_cfg
    with _lock:
        _current = None
        _current_cfg = None
        _agency_custody.clear()


def describe_current() -> Optional[dict]:
    c = get_custody()
    return c.describe() if c else None


if __name__ == "__main__":  # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(description="Polaris key custody (P1.2)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("describe", help="show the driver the environment selects (non-secret)")
    g = sub.add_parser("pkcs11-keygen", help="generate the ML-DSA-65 issuer key INSIDE a PKCS#11 token")
    g.add_argument("--module", required=True); g.add_argument("--token-label", default="polaris")
    g.add_argument("--pin-file", required=True); g.add_argument("--key-label", default="polaris-issuer")
    a = ap.parse_args()
    if a.cmd == "describe":
        print(json.dumps(describe_current(), indent=2))
    else:
        pk = pkcs11_generate_key(a.module, a.token_label, _read_secret_file(a.pin_file, "pkcs11 PIN"), a.key_label)
        print(json.dumps({"algorithm": ALGORITHM, "public_key_hex": pk.hex(), "fingerprint": fingerprint(pk),
                          "key_label": a.key_label, "token_label": a.token_label}, indent=2))
