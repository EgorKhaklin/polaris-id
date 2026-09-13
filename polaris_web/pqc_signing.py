"""polaris_web/pqc_signing.py — real ML-DSA-65 (FIPS 204) signing path.

v9.24. Until this module, Polaris's headline post-quantum claim was
rendered by a deterministic string in `token_value` -- the system's
headline claim was post-quantum signing and it was a deterministic
string. That is the critique this module exists to answer, and the
reason the placeholder below is labelled rather than silent.

This module integrates the FIPS 204 (ML-DSA-65) signing path via
liboqs-python (the Open Quantum Safe project's Python binding to the
liboqs C library). It is **gated behind POLARIS_USE_REAL_PQC=1**
(default OFF) so operators opt in deliberately after verifying their
deployment has the native library installed.

**Activation procedure (operator):**

    1. Install native liboqs (apt-get install liboqs-dev or build from
       https://github.com/open-quantum-safe/liboqs)
    2. pip install oqs (or pip install liboqs-python)
    3. Verify: python3 -c "import polaris_web.pqc_signing as p; print(p.availability_report())"
    4. Set POLARIS_USE_REAL_PQC=1 in production env
    5. This makes the `uc1_issue` route store real ML-DSA-65 signatures in
       `TokenSignature.signature_bytes` (and `sign()` / `verify()` produce
       and check real signatures).

**Wiring status (v9.58): WIRED.** `app.py`'s `uc1_issue` route calls
`signature_bytes_for_token()` and passes the result to
`uc1_issue_and_activate(..., p_signature_bytes := ...)`, so every token
issued through the app gets its `TokenSignature.signature_bytes` from this
module. With the flag unset (default) that is a deterministic SHA3-256
placeholder; with `POLARIS_USE_REAL_PQC=1` + liboqs it is a real ML-DSA-65
signature. The procedure COALESCEs to the legacy placeholder string only for
direct SQL callers that pass no signature, so existing tooling is unaffected.
`polaris_checks.check_pqc_signing_wired` asserts this wiring stays in place.

Per the two-witness principle (`docs/design/two-witness-principle.md`), the
ML-DSA-65 verify path is now **two-witnessed** (v9.133): the primary verdict
(liboqs) is cross-checked against an INDEPENDENT second witness — cryptography's
MLDSA65 (OpenSSL-backed, not liboqs) — and the two must AGREE (`verify_both`). A
disagreement is a cryptographic red flag and the signature is refused. When the
witness library is too old to provide ML-DSA, the verdict degrades to the lone
primary (the pre-v9.133 behaviour), so the second witness never weakens the path.

**Honest accounting:**

This module ships the integration. It does NOT migrate existing
tokens. Pre-v9.24 tokens carry deterministic `token_value` strings;
the verifier accepts them as a legacy class. The migration to
all-real-signatures is a separate operator decision documented in
docs/operator/PQC-MIGRATION.md.

**If `oqs` is not importable**, `is_available()` returns False and
`sign()` raises `PQCUnavailableError`. The flag-off default means
the rest of Polaris is unaffected. With flag-on but oqs missing,
token issuance fails fast (loud) rather than silently falling back
to the deterministic stub.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

try:  # roadmap P1.2 — the issuer key sits behind a custody driver
    import custody  # type: ignore
except ImportError:  # pragma: no cover
    from polaris_web import custody  # type: ignore


class PQCUnavailableError(RuntimeError):
    """Raised when POLARIS_USE_REAL_PQC=1 but oqs is not importable."""


class SigningError(RuntimeError):
    """Raised when a produced signature fails its own verification self-check —
    a real signature that does not verify against its key means broken key
    material or liboqs, and must never be persisted."""


# Detect liboqs-python at import time (defer ImportError so module
# always imports — callers introspect via is_available()).
_OQS_AVAILABLE = False
_OQS_IMPORT_ERROR: Optional[str] = None
_OQS_VERSION: Optional[str] = None

try:
    import oqs  # type: ignore
    _OQS_AVAILABLE = True
    _OQS_VERSION = getattr(oqs, "__version__", "unknown")
except ImportError as e:
    _OQS_IMPORT_ERROR = str(e)
    _OQS_AVAILABLE = False


# v9.133 — an INDEPENDENT second witness for the ML-DSA-65 verify path. The
# primary verifier above is liboqs; a LONE verifier means a bug or compromise in
# that single implementation would pass unnoticed (the two-witness discipline the
# ZK path already has in polaris_zk/witness2/). cryptography's MLDSA65 is a
# DIFFERENT FIPS 204 implementation (OpenSSL-backed, not liboqs) and is already a
# pinned dependency (the `cryptography==` line in requirements.txt is canonical;
# do not repeat the literal here, it drifts). Every real verdict is cross-checked
# against it; the two must AGREE. When the witness library is too old to provide
# ML-DSA, the verdict degrades to the lone primary (no worse than pre-v9.133).
_WITNESS_AVAILABLE = False
_WITNESS_IMPORT_ERROR: Optional[str] = None
_mldsa = None
_InvalidSignature = Exception  # overwritten on a successful import below
try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa  # type: ignore
    from cryptography.exceptions import InvalidSignature as _InvalidSignature  # type: ignore
    _WITNESS_AVAILABLE = hasattr(_mldsa, "MLDSA65PublicKey")
    if not _WITNESS_AVAILABLE:
        _WITNESS_IMPORT_ERROR = (
            "cryptography lacks MLDSA65PublicKey (needs cryptography>=48 + OpenSSL 3.5+)")
except Exception as e:  # cryptography too old / no ML-DSA
    _WITNESS_IMPORT_ERROR = str(e)
    _WITNESS_AVAILABLE = False


# FIPS 204 algorithm identifier used by liboqs (per OQS naming)
_ALG_NAME = "ML-DSA-65"                 # the default parameter set (historical name)
# P8.8a (v9.329): the accepted FIPS 204 parameter sets (custody.ACCEPTED_ALGORITHMS agrees;
# test_pqc_signing pins the two equal) and the cryptography witness class for each.
DEFAULT_ALGORITHM = "ML-DSA-65"
ACCEPTED_ALGORITHMS = ("ML-DSA-65", "ML-DSA-87")
_WITNESS_CLASSES = {"ML-DSA-65": "MLDSA65PublicKey", "ML-DSA-87": "MLDSA87PublicKey"}


def algorithm_for_public_key_hex(public_key_hex):
    """The accepted parameter set a public key's length identifies, or None."""
    try:
        return custody.algorithm_for_public_key(bytes.fromhex(public_key_hex or ""))
    except (ValueError, TypeError):
        return None


def algorithm_name(agency_id=None) -> str:
    """The parameter set signatures for `agency_id` (or the instance) are made under: the
    custodied key's when one is configured, else the configured default. Statement bodies
    carry this BEFORE signing, since `algorithm` is a signed field."""
    try:
        cust = custody.get_custody_for_agency(agency_id) if agency_id is not None else custody.get_custody()
    except custody.CustodyError:
        cust = None
    if cust is not None:
        return cust.algorithm
    try:
        return custody.configured_algorithm()
    except custody.CustodyError:
        return DEFAULT_ALGORITHM


@dataclass(frozen=True)
class SigningResult:
    """One signed token's outputs.

    `algorithm_name` ties to the CryptographicAlgorithm table row (C7).
    `public_key_hex` is the verifier's lookup key.
    `signature_hex` is what gets stored alongside token_value.
    `message_hash_hex` is the hash that was signed (sha3_256(token_value)).
    """
    algorithm_name: str
    public_key_hex: str
    signature_hex: str
    message_hash_hex: str


def is_available() -> bool:
    """True iff liboqs-python is importable.

    Cheap; safe to call from request paths to short-circuit.
    """
    return _OQS_AVAILABLE


def is_enabled() -> bool:
    """True iff POLARIS_USE_REAL_PQC=1 AND oqs is available.

    Production check — issuance code uses this as the gate. The flag
    must be set explicitly; we never silently enable.
    """
    flag_set = os.environ.get("POLARIS_USE_REAL_PQC", "0") == "1"
    return flag_set and _OQS_AVAILABLE


def _custody_report():
    try:
        return custody.describe_current()
    except custody.CustodyError as exc:
        return {"error": str(exc)}


def availability_report() -> dict:
    """Structured introspection for operators + CI.

    Used by `scripts/polaris-pqc-status.sh` to render a clear
    operator message.
    """
    return {
        "module_imported": True,
        "oqs_available": _OQS_AVAILABLE,
        "oqs_version": _OQS_VERSION,
        "oqs_import_error": _OQS_IMPORT_ERROR,
        # v9.133 — the independent second witness (cryptography/OpenSSL).
        "second_witness_available": _WITNESS_AVAILABLE,
        "second_witness_error": _WITNESS_IMPORT_ERROR,
        "flag_set": os.environ.get("POLARIS_USE_REAL_PQC", "0") == "1",
        "is_enabled": is_enabled(),
        "algorithm": algorithm_name(),
        "accepted_algorithms": list(ACCEPTED_ALGORITHMS),
        # roadmap P1.2 — which custody holds the issuer key (non-secret facts;
        # None = no persistent key, the ephemeral dev fallback). A misconfigured
        # custody is reported as an error string rather than raising here.
        "custody": _custody_report(),
        "notes": (
            "Real signing ships behind POLARIS_USE_REAL_PQC=1 (v9.24); without "
            "it the signature is a labelled 32-byte SHA3-256 placeholder that "
            "verifies against no key. Migration of existing token_value entries "
            "is a separate operator decision. What a break in the lattice "
            "assumptions would and would not cost is in PRODUCTION-READINESS.md."
        ),
    }


# Long-lived signing keypair. Production sets POLARIS_PQC_SIGNING_KEY_FILE to a
# JSON file {algorithm, secret_key_hex, public_key_hex} (mode 0600). The private
# key is the issuer's signing key — in a real deployment it belongs in an HSM/KMS;
# this file is the loading MECHANISM the operator points at their custodied
# material. When set, every signature uses the SAME key, so its public key is a
# stable, publishable trust anchor that verifiers check against. When unset
# (dev/test), sign() falls back to an ephemeral per-call keypair, which is NOT
# verifiable against any known anchor and must never be the production path.
_PERSISTENT_KEY_ENV = "POLARIS_PQC_SIGNING_KEY_FILE"
_PERSISTENT_KEYPAIR: Optional[tuple] = None
_PERSISTENT_LOADED = False


def _load_persistent_keypair() -> Optional[tuple]:
    """Legacy accessor kept for callers/tests: (secret_key, public_key) when the
    custody driver is the FILE driver, None when no persistent key is configured.
    Non-file drivers (pkcs11, awskms) never expose a secret key, so this returns
    None for them; use `custody.get_custody()` directly. Raises loudly on a
    malformed key file (a bad signing key must not silently degrade to ephemeral)."""
    global _PERSISTENT_KEYPAIR, _PERSISTENT_LOADED
    cust = custody.get_custody()
    if isinstance(cust, custody.FileCustody):
        _PERSISTENT_KEYPAIR = cust.keypair()
    else:
        _PERSISTENT_KEYPAIR = None
    _PERSISTENT_LOADED = True
    return _PERSISTENT_KEYPAIR


def generate_keypair(algorithm=None) -> dict:
    """Generate a fresh keypair for POLARIS_PQC_SIGNING_KEY_FILE under `algorithm` (an
    accepted parameter set; default POLARIS_PQC_ALGORITHM, else ML-DSA-65).

    Returns {algorithm, secret_key_hex, public_key_hex}. The secret key is the
    issuer's long-lived signing key: write it to a 0600 file (or load it into an
    HSM/KMS) and publish the public key as the verification trust anchor.
    """
    if not _OQS_AVAILABLE:
        raise PQCUnavailableError(
            f"liboqs-python is not importable: {_OQS_IMPORT_ERROR}.")
    import oqs as _oqs  # type: ignore
    alg = algorithm or custody.configured_algorithm()
    if alg not in ACCEPTED_ALGORITHMS:
        raise ValueError(f"{alg!r} is not an accepted algorithm ({', '.join(ACCEPTED_ALGORITHMS)})")
    with _oqs.Signature(alg) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return {
        "algorithm": alg,
        "secret_key_hex": secret_key.hex(),
        "public_key_hex": public_key.hex(),
    }


def sign(message: bytes, agency_id=None) -> SigningResult:
    """Sign `message` with ML-DSA-65.

    Uses the custodied long-lived key when one is configured (the file driver via
    POLARIS_PQC_SIGNING_KEY_FILE, or a PKCS#11 / AWS KMS driver via
    POLARIS_CUSTODY_DRIVER; see custody.py), so the public key is a stable trust
    anchor; otherwise generates an ephemeral per-call keypair (the dev/test
    fallback — not verifiable against a known anchor).

    PE.3b: when `agency_id` is given, the ISSUING AGENCY's own key is used if one is
    configured (POLARIS_AGENCY_KEYS_DIR/<agency_id>.json), else the global key — so a
    token is signed by the agency it is issued for, and single-key deployments are
    unchanged.

    Raises PQCUnavailableError if oqs is not importable.
    Returns SigningResult with public_key, signature, message hash.
    """
    if not _OQS_AVAILABLE:
        raise PQCUnavailableError(
            f"liboqs-python is not importable: {_OQS_IMPORT_ERROR}. "
            "Install per polaris_web/pqc_signing.py module docstring."
        )

    # Deferred import (mypy/IDE don't see it pre-import)
    import oqs as _oqs  # type: ignore

    # SHA3-256 the message for binding to a fixed-size digest
    digest = hashlib.sha3_256(message).digest()

    # roadmap P1.2 — the custodied key (file, pkcs11, or awskms driver) signs
    # the digest; the driver returns raw ML-DSA-65 bytes, so nothing downstream
    # (storage, the two-witness verify) can tell which custody produced them.
    # PE.3b: pick the issuing agency's key when one is registered.
    cust = custody.get_custody_for_agency(agency_id) if agency_id is not None else custody.get_custody()
    if cust is not None:
        alg = cust.algorithm
        public_key = cust.public_key()
        signature = cust.sign(digest)
    else:
        # No persistent key configured — ephemeral keypair (dev/test only).
        alg = custody.configured_algorithm()
        with _oqs.Signature(alg) as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(digest)

    return SigningResult(
        algorithm_name=alg,
        public_key_hex=public_key.hex(),
        signature_hex=signature.hex(),
        message_hash_hex=digest.hex(),
    )


# Label recorded for the dependency-free placeholder so it can never be
# mistaken for a real signature in logs, tests, or operator tooling.
PLACEHOLDER_LABEL = "DETERMINISTIC-PLACEHOLDER-SHA3-256"


def signature_bytes_for_token(token_value: str) -> tuple:
    """Produce the bytes stored in `TokenSignature.signature_bytes` at issuance.

    This is the single entry point the issuance route (`uc1_issue`) calls, so
    token issuance routes through this module rather than writing a hardcoded
    SQL placeholder. Returns `(signature_bytes, algorithm_label)`:

    - **Flag unset (default, including CI):** a deterministic SHA3-256 binding
      of `token_value`. This is NOT a cryptographic signature (there is no
      private key); it is a reproducible placeholder that lets the reference
      implementation run without the native library. Label: `PLACEHOLDER_LABEL`.
    - **`POLARIS_USE_REAL_PQC=1` + liboqs available:** a real ML-DSA-65
      (FIPS 204) signature over `token_value`. Label: `"ML-DSA-65"`.
    - **Flag set but liboqs unavailable:** raises `PQCUnavailableError` (fail
      loud; never silently downgrade an operator who asked for real PQC).

    The caller stores the bytes in `TokenSignature.signature_bytes` and records
    the algorithm in `TokenSignature.algorithm_id` (C7: algorithm by reference).
    """
    sig, label, _pk = signature_with_key_for_token(token_value)
    return sig, label


def signature_with_key_for_token(token_value: str, agency_id=None) -> tuple:
    """Like `signature_bytes_for_token`, but also returns the signing PUBLIC KEY.

    Returns `(signature_bytes, algorithm_label, public_key_hex_or_none)`. The
    caller stores the public key WITH the signature (TokenSignature.
    signing_public_key_hex) so verification at use is self-contained — no live
    trust-anchor lookup, and it survives key rotation. For the placeholder path
    the third element is None (there is no key).

    PE.3b: `agency_id` selects the issuing agency's own signing key when one is
    registered (POLARIS_AGENCY_KEYS_DIR), else the global key. The placeholder path
    ignores it (there is no key to pick).
    """
    flag_set = os.environ.get("POLARIS_USE_REAL_PQC", "0") == "1"
    if flag_set and not _OQS_AVAILABLE:
        raise PQCUnavailableError(
            "POLARIS_USE_REAL_PQC=1 but liboqs-python is not importable: "
            f"{_OQS_IMPORT_ERROR}. Install per this module's docstring or unset the flag."
        )
    if flag_set:
        # flag_set AND _OQS_AVAILABLE (otherwise we raised above)
        # v9.264: real issuance is where the two-witness claim is MADE ("every
        # stored production signature was independently verified by two
        # implementations"). It may only be made if the second witness is
        # actually present, so refuse up front when it is not — rather than let
        # verify_both silently fall back to the lone primary. (The verify-at-use
        # and display paths still tolerate a missing witness; issuance does not.)
        if not second_witness_available():
            raise SigningError(
                "real ML-DSA-65 issuance requires the independent second witness "
                "(cryptography/OpenSSL MLDSA65) so every stored signature is genuinely "
                "two-witnessed; it is unavailable "
                f"({_WITNESS_IMPORT_ERROR or 'no ML-DSA support'}). Install cryptography>=48 on "
                "OpenSSL 3.5+, or use the placeholder path (unset POLARIS_USE_REAL_PQC).")
        result = sign(token_value.encode("utf-8"), agency_id=agency_id)
        # Enforce verification on the issuance path: the signature we just
        # produced MUST verify against its own public key before it is handed to
        # the DB. v9.133 — verify with BOTH witnesses (liboqs + the independent
        # cryptography/OpenSSL impl); they must AGREE. require_witness=True (v9.264)
        # makes a missing witness a REFUSAL, not a downgrade to one implementation:
        # a real signature that fails to self-verify means broken key material or
        # liboqs, and a two-witness DISAGREEMENT means one implementation is wrong —
        # either way, refuse to persist a signature the two verifiers do not both accept.
        if not verify_both(token_value.encode("utf-8"), result.signature_hex,
                           result.public_key_hex, require_witness=True):
            raise SigningError(
                "produced ML-DSA-65 signature failed two-witness self-verification; refusing to issue")
        return bytes.fromhex(result.signature_hex), result.algorithm_name, result.public_key_hex
    # Flag off: deterministic, dependency-free placeholder (not a signature).
    digest = hashlib.sha3_256(token_value.encode("utf-8")).digest()
    return digest, PLACEHOLDER_LABEL, None


def signature_over_message(message: bytes, agency_id=None) -> tuple:
    """Sign an arbitrary message with the issuer's ML-DSA-65 key (P3.6, the offline
    status assertion). Mirrors `signature_with_key_for_token` but over `message`
    rather than a token_value: real ML-DSA-65 (two-witness self-checked) when
    POLARIS_USE_REAL_PQC=1 and liboqs is present, else the deterministic
    SHA3-256 placeholder. Returns `(signature_bytes, algorithm_label,
    public_key_hex_or_none)`; the signer/verifier both bind to SHA3-256(message)."""
    flag_set = os.environ.get("POLARIS_USE_REAL_PQC", "0") == "1"
    if flag_set and not _OQS_AVAILABLE:
        raise PQCUnavailableError(
            "POLARIS_USE_REAL_PQC=1 but liboqs-python is not importable: "
            f"{_OQS_IMPORT_ERROR}. Install per this module's docstring or unset the flag.")
    if flag_set:
        if not second_witness_available():
            raise SigningError(
                "real ML-DSA-65 status-assertion signing requires the independent second witness "
                "(cryptography/OpenSSL MLDSA65); it is unavailable "
                f"({_WITNESS_IMPORT_ERROR or 'no ML-DSA support'}). Install cryptography>=48 on "
                "OpenSSL 3.5+, or use the placeholder path (unset POLARIS_USE_REAL_PQC).")
        result = sign(message, agency_id=agency_id)
        if not verify_both(message, result.signature_hex, result.public_key_hex, require_witness=True):
            raise SigningError(
                "produced ML-DSA-65 status assertion failed two-witness self-verification; refusing to sign")
        return bytes.fromhex(result.signature_hex), result.algorithm_name, result.public_key_hex
    # Flag off: deterministic, dependency-free placeholder (not a signature).
    return hashlib.sha3_256(message).digest(), PLACEHOLDER_LABEL, None


def signature_for_migration(token_value: str, algorithm: str, agency_id=None) -> tuple:
    """Sign `token_value` under an EXPLICIT target parameter set (P7.6, the quantum event).

    Every other signing entry point takes its algorithm from process-wide configuration,
    which is right while one parameter set is operational. A migration is the case where two
    are: the instance keeps issuing under the current algorithm while the existing population
    is re-signed under the new one, so the target has to be an argument rather than an
    environment variable.

    The key comes from custody.get_custody_for_algorithm, which REFUSES when no key exists
    for the requested set rather than signing under whatever key it has. That refusal is the
    point: a signature made with ML-DSA-65 and stored against algorithm_id 2 is a false label
    on a real signature in the audit-of-record, and every later verification would attempt
    ML-DSA-87, fail, and look exactly like tampering.

    Returns `(signature_bytes, algorithm_label, public_key_hex_or_none)`, matching
    `signature_over_message`. With the flag off, the deterministic placeholder is returned
    and labelled as such, so a dev-profile migration can be exercised end to end without
    anything mistaking its output for a signature."""
    flag_set = os.environ.get("POLARIS_USE_REAL_PQC", "0") == "1"
    if not flag_set:
        # The placeholder is per (token, algorithm): a migration that produced the same bytes
        # for both parameter sets would let a drill "pass" while proving nothing changed.
        return (hashlib.sha3_256(f"{algorithm}|{token_value}".encode()).digest(),
                PLACEHOLDER_LABEL, None)
    if not _OQS_AVAILABLE:
        raise PQCUnavailableError(
            "POLARIS_USE_REAL_PQC=1 but liboqs-python is not importable: "
            f"{_OQS_IMPORT_ERROR}. Install per this module's docstring or unset the flag.")
    if not second_witness_available():
        raise SigningError(
            "a migration signature requires the independent second witness; refusing to "
            f"re-sign a population on one implementation ({_WITNESS_IMPORT_ERROR or 'none'})")
    import oqs as _oqs  # type: ignore
    digest = hashlib.sha3_256(token_value.encode("utf-8")).digest()
    cust = custody.get_custody_for_algorithm(algorithm)
    if cust is not None:
        public_key, signature = cust.public_key(), cust.sign(digest)
    else:
        with _oqs.Signature(algorithm) as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(digest)
    public_key_hex, signature_hex = public_key.hex(), signature.hex()
    # Self-verify under BOTH witnesses before the row is written. A migration writes once
    # across a whole population; a signature nobody checked at the moment it was made is a
    # population-wide defect discovered by holders.
    if not verify_both(token_value.encode("utf-8"), signature_hex, public_key_hex,
                       require_witness=True, algorithm=algorithm):
        raise SigningError(
            f"a {algorithm} migration signature failed two-witness self-verification; "
            "refusing to write it")
    return signature, algorithm, public_key_hex


def verify_stored_signature(
    token_value: str,
    signature_bytes: bytes,
    signing_public_key_hex: Optional[str],
    witnesses: str = "both",
) -> bool:
    """Verify a stored TokenSignature against its token using the public key
    stored WITH the signature — self-contained, no live trust-anchor lookup.

    - ``signing_public_key_hex`` non-empty: a real ML-DSA-65 signature, verified
      against that key (a genuine authenticity proof). Returns False if liboqs is
      unavailable (a real signature cannot be checked without it).
    - ``signing_public_key_hex`` None/empty: the deterministic SHA3-256
      placeholder; an integrity recompute + constant-time compare (NOT an
      authenticity proof — there is no key).

    ``witnesses`` selects the strength of the real-signature check:
    - ``"both"`` (default): two independent verifiers (liboqs AND OpenSSL) must
      agree — the issuance-grade check. Issuance always uses this before it will
      persist a signature.
    - ``"single"``: one witness (liboqs) only — the verify-AT-USE path, ~10x
      faster. It is sound because a stored real signature was already
      two-witnessed at issuance (both implementations accepted it), so a single
      witness at use re-confirms authenticity at the throughput a national
      deployment needs. See docs/design/verification-scaling.md.
    The placeholder path is unaffected (it does no crypto).
    """
    if signing_public_key_hex:
        if not _OQS_AVAILABLE:
            return False
        message = token_value.encode("utf-8")
        signature_hex = signature_bytes.hex()
        if witnesses == "single":
            return verify(message, signature_hex, signing_public_key_hex)
        return verify_both(message, signature_hex, signing_public_key_hex)
    import hmac
    expected = hashlib.sha3_256(token_value.encode("utf-8")).digest()
    return hmac.compare_digest(signature_bytes, expected)


def verify(
    message: bytes,
    signature_hex: str,
    public_key_hex: str,
    algorithm=None,
) -> bool:
    """Verify a signature against (message, public_key).

    Returns True if the signature is valid. Returns False on any
    verification failure (does NOT raise — verification is a binary
    yes/no for the calling code).

    Raises PQCUnavailableError if oqs is not importable.
    """
    if not _OQS_AVAILABLE:
        raise PQCUnavailableError(
            f"liboqs-python is not importable: {_OQS_IMPORT_ERROR}"
        )

    import oqs as _oqs  # type: ignore

    digest = hashlib.sha3_256(message).digest()
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False

    alg = algorithm or custody.algorithm_for_public_key(public_key)
    if not isinstance(alg, str) or alg not in ACCEPTED_ALGORITHMS:
        return False
    try:
        with _oqs.Signature(alg) as verifier:
            return verifier.verify(digest, signature, public_key)
    except Exception:
        return False


def second_witness_available() -> bool:
    """True iff the independent (cryptography/OpenSSL) ML-DSA-65 witness can run."""
    return _WITNESS_AVAILABLE


def _verify_second_witness(message: bytes, signature_hex: str, public_key_hex: str, algorithm=None):
    """Independent ML-DSA-65 verify via cryptography/OpenSSL — NOT liboqs.

    Returns True/False (the witness's verdict), or None when the witness cannot
    run (library too old, or it cannot even load the key) so the caller falls back
    to the lone primary. Verifies the SAME SHA3-256 digest the signer signs.
    """
    if not _WITNESS_AVAILABLE:
        return None
    try:
        pk_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    try:
        alg = algorithm or custody.algorithm_for_public_key(pk_bytes)
        cls = getattr(_mldsa, _WITNESS_CLASSES.get(alg, "") if isinstance(alg, str) else "", None)
        if cls is None:
            return None  # no witness implements this parameter set
        pk = cls.from_public_bytes(pk_bytes)
    except Exception:
        return None  # the witness cannot load this key — it cannot witness
    digest = hashlib.sha3_256(message).digest()
    try:
        pk.verify(sig_bytes, digest)
        return True
    except _InvalidSignature:
        return False
    except Exception:
        # A malformed signature the witness cannot parse is, to it, not valid.
        return False


def verify_both(message: bytes, signature_hex: str, public_key_hex: str,
                *, require_witness: bool = False, algorithm=None) -> bool:
    """Two-witness ML-DSA-65 verify (v9.133): the primary (liboqs) AND an
    independent second witness (cryptography/OpenSSL) must AGREE the signature is
    valid. A DISAGREEMENT (one accepts, one rejects) is a cryptographic red flag —
    a bug or compromise in one implementation, or tampering a lone verifier would
    miss — so the verdict is False and the disagreement is logged loudly.

    When the witness library is unavailable it returns None; by default the lone
    primary verdict then stands (no worse than before v9.133), which is fine for
    the re-verification (display) path. But issuance passes ``require_witness=True``
    (v9.264): a stored signature may only claim to be two-witnessed if the second
    witness actually ran, so a missing witness is a REFUSAL, not a silent
    downgrade to one implementation. Raises PQCUnavailableError if the PRIMARY
    (oqs) is unavailable.
    """
    primary = verify(message, signature_hex, public_key_hex, algorithm=algorithm)
    witness = _verify_second_witness(message, signature_hex, public_key_hex, algorithm=algorithm)
    if witness is None:
        if require_witness:
            sys.stderr.write(
                "PQC SECOND WITNESS UNAVAILABLE on a required two-witness check "
                "(issuance): refusing to certify a signature as two-witnessed when "
                "only one implementation verified it.\n")
            return False
        return primary
    if primary != witness:
        sys.stderr.write(
            "PQC SECOND-WITNESS DISAGREEMENT: liboqs=%s cryptography=%s on a ML-DSA-65 "
            "signature — refusing to trust it (a lone verifier would have missed this).\n"
            % (primary, witness))
        return False
    return primary


def trust_anchor_public_key_hex() -> Optional[str]:
    """The published trust anchor: the custodied signing key's public key (hex).

    This is the key a verifier checks token signatures against. Returns None when
    no custody is configured (no persistent key), since there is then no stable,
    publishable anchor, only per-process ephemeral keys, so a real signature
    cannot be verified at use.
    """
    cust = custody.get_custody()
    if cust is None:
        return None
    return cust.public_key().hex()


_TRUST_ANCHORS_ENV = "POLARIS_PQC_TRUST_ANCHORS_FILE"


def trust_anchor_public_keys() -> list:
    """All acceptable anchors, hex: the CURRENT custodied key first, then the
    previous keys listed in POLARIS_PQC_TRUST_ANCHORS_FILE (a JSON document
    {"anchors": [{"public_key_hex": ..., "label": ..., "retired": ...}]}). This is
    what makes key rotation possible: tokens signed under a previous key keep
    verifying until the operator removes that anchor (KEY-CEREMONY.md).
    A malformed anchors file fails loud rather than silently shrinking trust."""
    anchors = []
    current = trust_anchor_public_key_hex()
    if current:
        anchors.append(current)
    path = os.environ.get(_TRUST_ANCHORS_ENV)
    if path:
        try:
            with open(path) as fh:
                doc = json.load(fh)
            for entry in doc.get("anchors", []):
                pk = entry["public_key_hex"]
                bytes.fromhex(pk)
                if pk not in anchors:
                    anchors.append(pk)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise RuntimeError(f"{_TRUST_ANCHORS_ENV}={path} is unreadable/malformed: {exc}") from exc
    return anchors


def verify_token_signature(
    token_value: str,
    signature_bytes: bytes,
    algorithm_label: str,
) -> bool:
    """Verify a stored `TokenSignature` against its token — the use-path check.

    Dispatch on the algorithm recorded WITH the signature (not the current
    process mode), so a token signed under one mode verifies correctly later:

    - ``"ML-DSA-65"`` — a real signature. Verified against the trust-anchor
      public key (`trust_anchor_public_key_hex`). Returns False when no trust
      anchor is configured (cannot prove authenticity without it) or the
      signature does not check out. This is a genuine authenticity proof: only
      the holder of the anchor's private key could have produced it.
    - ``PLACEHOLDER_LABEL`` — the deterministic SHA3-256 binding. Verification is
      an integrity recompute + constant-time compare. This is NOT an authenticity
      proof (there is no key); it only confirms the bytes match `token_value`.
    - anything else — False (unknown signature scheme).
    """
    if algorithm_label in ACCEPTED_ALGORITHMS:
        anchors = trust_anchor_public_keys()
        if not anchors:
            return False
        # The current key first, then any previous keys still trusted (rotation).
        return any(verify_both(token_value.encode("utf-8"), signature_bytes.hex(), a, algorithm=algorithm_label)
                   for a in anchors)
    if algorithm_label == PLACEHOLDER_LABEL:
        import hmac
        expected = hashlib.sha3_256(token_value.encode("utf-8")).digest()
        return hmac.compare_digest(signature_bytes, expected)
    return False


def smoke_test() -> bool:
    """Roundtrip: sign + verify a known message.

    Returns True if both succeed and verifier accepts. Used by CI
    and by scripts/polaris-pqc-status.sh to confirm working state.
    Returns False on any failure (graceful — caller decides whether
    to escalate).
    """
    if not _OQS_AVAILABLE:
        return False
    msg = b"polaris-pqc-smoke-test-v9.24"
    try:
        result = sign(msg)
        # Exercise the two-witness path (v9.133): when the cryptography witness
        # is present this confirms BOTH implementations agree, not just liboqs.
        return verify_both(msg, result.signature_hex, result.public_key_hex)
    except Exception:
        return False
