# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""verifier.py -- the listening half: ask for a presentation, and answer 200 or 4xx.

`sdjwt.py` decides and `jwe.py` opens. This is what puts them on a wire. It builds the
OpenID4VP 1.0 authorization request the High Assurance Interoperability Profile requires,
serves it at a `request_uri`, receives the wallet's `direct_post.jwt` POST, and answers.

**The answer IS the result.** Seven of the eleven modules in
`oid4vp-1final-verifier-haip-test-plan` are negative: the wallet sends a presentation broken
in one specific way, and the module passes automatically if the verifier responds 4xx. So
every refusal `sdjwt` or `jwe` can produce has to become a 4xx here, and a verifier that
swallows a bad presentation and returns 200 is not merely wrong, it fails seven tests at once
in a way that looks like nothing happening.

WHAT THE PROFILE PINS, none of it optional, all of it measured against the running suite
rather than read off the specification (see `lab/interop/`):

    client_id_prefix    x509_hash, so the client_id is the SHA-256 of the leaf certificate
    request_method      request_uri_signed, so the request object is a signed JAR with an
                        x5c header, fetched over HTTPS, and the trust anchor is registered
                        out of band and MUST NOT be in the chain
    response_mode       direct_post.jwt, so the response comes back encrypted
    client_metadata     exactly three keys: jwks, vp_formats_supported, and
                        encrypted_response_enc_values_supported carrying BOTH A128GCM and
                        A256GCM. A fourth key is a warning; the older
                        authorization_encrypted_response_* names are a failure
    the direct_post
    response body       HTTP 200, application/json, and ONLY a redirect_uri (HAIP 5.1)

A FRESH ENCRYPTION KEY PER REQUEST. The suite checks that the key in `client_metadata.jwks`
is not reused between tests, and it is right to: one long-lived response-encryption key makes
every presentation ever sent to this verifier readable by anybody who later obtains it.
"""
import base64
import json
import re
import secrets
import threading
import time

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.x509 import load_pem_x509_certificate
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

from .jwe import (ACCEPTED_ALG, ACCEPTED_ENC, JweError, _loads_depth_bounded,
                  _public_key_from_jwk, b64u_decode, b64u_encode, decrypt_response,
                  encrypt_compact)
from .sdjwt import (ALL_ENTRIES, PER_CREDENTIAL, TRANSACTION_DATA_HASH_ALGS,
                    TRANSACTION_DATA_SCOPES, JtiMemory, TransactionDataBinding,
                    TransactionDataEntry, Verdict, verify_presentation)

#: How long an outstanding request stays answerable. A nonce that is accepted forever is not
#: a nonce; this is the other half of the key binding JWT's own freshness check, on our side,
#: where we control it.
DEFAULT_REQUEST_TTL_SECONDS = 300

#: The audience of a request object, fixed by OpenID4VP 1.0 for a wallet that is not a
#: specific named entity.
WALLET_AUDIENCE = "https://self-issued.me/v2"

#: The response mode HAIP pins and every request here names. TS12 section 3.6 has the key
#: binding JWT of an SCA presentation repeat it.
RESPONSE_MODE = "direct_post.jwt"

#: The fresh value an accepted response's `redirect_uri` carries, as its `response_code`. OpenID4VP
#: 1.0 section 8.2: a Verifier that answers with a redirect URI "MUST include a fresh,
#: cryptographically random value in the URL", so that "only the receiver of the redirect can
#: fetch and process the Authorization Response"; 128 bits or more is RECOMMENDED. 16 bytes.
RESPONSE_CODE_BYTES = 16

#: How long a verifier remembers a TS12 `jti` it has checked: a day. TS12 3.6 makes the value
#: unique to each presentation; memory is per Verifier instance and bounded, and a relying party
#: that needs a register for longer records `verdict.transaction_data["jti"]` in its own.
JTI_RETENTION_SECONDS = 24 * 3600

#: OpenID4VP 1.0 section 6.1, a Credential Query's id: "a non-empty string consisting of
#: alphanumeric, underscore (_), or hyphen (-) characters."
_DCQL_ID = re.compile(r"[A-Za-z0-9_-]+")

#: The `error` of an Authorization Error Response this verifier processes. OpenID4VP 1.0
#: section 8.5 follows RFC 6749, whose syntax is one or more of %x20-21 / %x23-5B / %x5D-7E
#: (section 4.1.2.1); every code RFC 6749, OpenID Connect and OpenID4VP define, and every one in
#: IANA's OAuth Extensions Error Registry, is letters and underscores. This is that shape,
#: bounded at 64. The rest of the syntax, a space or a `<` among them, would let a sender write
#: `<- 200 authentic` into the line `serve` prints, which is what the lab walks grep for.
_ERROR_CODE = re.compile(r"[A-Za-z0-9_]{1,64}")

#: The most of a wallet's `error_description` an operator is shown (`_printable`).
ERROR_DESCRIPTION_MAX = 200

#: TS12's payment transaction type (section 4.3.1).
TS12_PAYMENT = "urn:eudi:sca:payment:1"

#: TS12's JSON Schema for the `payload` of a urn:eudi:sca:payment:1 entry, as published at
#: eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/docs/technical-specifications/api/ts12-urn-eudi-sca-payment-1-data-model.json
#: (commit ee91a294, git blob 0c9a0c60). TS12 v1.0.1, (c) European Union 2025-2026, CC BY 4.0
#: (https://creativecommons.org/licenses/by/4.0/). Transcribed from JSON into this mapping, with
#: `$schema`, `examples` and `format` left out: `format` is an annotation in JSON Schema 2020-12,
#: not an assertion, so a validator does not apply it by default and neither does this one.
#: lab/interop/transaction-data/ fetches the file at that commit and holds this mapping to it.
_TS12_PAYMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "transaction_id": {"type": "string", "maxLength": 36, "minLength": 1},
        "date_time": {"type": "string"},
        "payee": {"type": "object",
                  "properties": {"name": {"type": "string"}, "id": {"type": "string"},
                                 "logo": {"type": "string"}, "website": {"type": "string"}},
                  "required": ["name", "id"]},
        "pisp": {"type": "object",
                 "properties": {"legal_name": {"type": "string"}, "brand_name": {"type": "string"},
                                "domain_name": {"type": "string"}},
                 "required": ["legal_name", "brand_name", "domain_name"]},
        "execution_date": {"type": "string"},
        "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
        "amount": {"type": "number"},
        "amount_estimated": {"type": "boolean"},
        "amount_earmarked": {"type": "boolean"},
        "sct_inst": {"type": "boolean"},
        "recurrence": {
            "type": "object",
            "properties": {
                "start_date": {"type": "string"},
                "end_date": {"type": "string"},
                "number": {"type": "integer"},
                "frequency": {"type": "string",
                              "enum": ["INDA", "DAIL", "WEEK", "TOWK", "TWMN", "MNTH", "TOMN",
                                       "QUTR", "FOMN", "SEMI", "YEAR", "TYEA"]},
                "mit_options": {"type": "object",
                                "properties": {"amount_variable": {"type": "boolean"},
                                               "min_amount": {"type": "number"},
                                               "max_amount": {"type": "number"},
                                               "total_amount": {"type": "number"},
                                               "initial_amount": {"type": "number"},
                                               "initial_amount_number": {"type": "integer"},
                                               "apr": {"type": "number"}}},
            },
            "required": ["frequency"],
        },
    },
    "required": ["transaction_id", "payee", "currency", "amount"],
    "additionalProperties": False,
}

#: JSON Schema's types over what `json.loads` returns. A boolean is not a number, and 2020-12
#: counts a number with no fractional part as an integer, 1.0 included.
_JSON_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: ((isinstance(v, int) and not isinstance(v, bool))
                          or (isinstance(v, float) and v.is_integer())),
}


def _schema_problems(value, schema, where):
    """What `schema` refuses in `value`, for the keywords TS12's payment schema uses: type,
    properties, required, additionalProperties, minLength, maxLength, pattern and enum."""
    if not _JSON_TYPES[schema["type"]](value):
        return ["%s is not a JSON %s" % (where, schema["type"])]
    problems = []
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            problems.append("%s is shorter than %d characters" % (where, schema["minLength"]))
        if len(value) > schema.get("maxLength", len(value)):
            problems.append("%s is longer than %d characters" % (where, schema["maxLength"]))
        # ECMA-262, as JSON Schema specifies: `$` ends the input. Python's `$` also matches
        # before a final newline, so "EUR\n" would pass it.
        pattern = schema.get("pattern")
        if pattern is not None and not re.search(
                pattern[:-1] + r"\Z" if pattern.endswith("$") else pattern, value):
            problems.append("%s does not match %s" % (where, pattern))
        if "enum" in schema and value not in schema["enum"]:
            problems.append("%s is %r, not one of %s" % (where, value, ", ".join(schema["enum"])))
    if isinstance(value, dict):
        for name in schema.get("required", ()):
            if name not in value:
                problems.append("%s has no %s" % (where, name))
        members = schema.get("properties", {})
        for name, member in value.items():
            if name in members:
                problems.extend(_schema_problems(member, members[name], "%s.%s" % (where, name)))
            elif schema.get("additionalProperties", True) is False:
                problems.append("%s carries %r, which the schema does not allow" % (where, name))
    return problems


def ts12_payment_problems(payload):
    """Why `payload` does not satisfy TS12's JSON Schema for urn:eudi:sca:payment:1, one sentence
    per problem; an empty list when it does. The schema is TS12's own (above), never one written
    here: a wallet validates a payment against it (TS12 3.2, step 4) and refuses what it refuses.
    TS12's prose rules that the schema does not encode (an execution_date not in the past, none
    beside a recurrence) are not checked."""
    return _schema_problems(payload, _TS12_PAYMENT_SCHEMA, "payload")


def transaction_data_entries(entries, credential_ids):
    """`transaction_data` for a request object (OpenID4VP 1.0 section 5.1), refused here, at
    construction, when a wallet would refuse it, rather than sent.

    `entries` is a non-empty list. A string is sent exactly as given, so a vector's `raw` reaches
    the wallet byte for byte and its published hashes apply. An object is encoded here, as compact
    UTF-8 JSON in unpadded base64url. Either way the string the request carries is the one the
    hashes are checked over. Each must decode to an object with a non-empty string `type` and
    `credential_ids` naming this request's credential queries, each once. A
    `transaction_data_hashes_alg` is a non-empty array (B.3.3.1) naming an algorithm this
    verifier computes, and the entries must share one, since one key binding JWT binds them with
    one. A TS12 type (urn:eudi:sca:...) carries a `payload` object (TS12 section 4.2), and a
    payment's must satisfy TS12's schema for it (ts12_payment_problems). Returns a tuple of
    TransactionDataEntry; raises ValueError naming the entry and the rule.
    """
    if not isinstance(entries, (list, tuple)) or not entries:
        raise ValueError("transaction_data must be a non-empty JSON array of entries")
    out = []
    for position, item in enumerate(entries):
        if isinstance(item, dict):
            raw = b64u_encode(json.dumps(item, separators=(",", ":"), ensure_ascii=False)
                              .encode("utf-8"))
        elif isinstance(item, str):
            raw = item
        else:
            raise ValueError("transaction_data entry %d is a JSON %s; an entry is a base64url "
                             "string or a JSON object" % (position, type(item).__name__))
        try:
            entry = TransactionDataEntry(raw)
        except ValueError as exc:
            raise ValueError("transaction_data entry %d: %s" % (position, exc)) from None
        if not isinstance(entry.document.get("transaction_data_hashes_alg", []), list):
            raise ValueError("transaction_data entry %d: transaction_data_hashes_alg is an array "
                             "(OpenID4VP 1.0 B.3.3.1), not a bare string" % position)
        if entry.hashes_alg is not None and not set(entry.hashes_alg) & set(TRANSACTION_DATA_HASH_ALGS):
            raise ValueError("transaction_data entry %d allows %s, none of which this verifier "
                             "computes (%s)" % (position, ", ".join(entry.hashes_alg),
                                                ", ".join(sorted(TRANSACTION_DATA_HASH_ALGS))))
        unknown = [i for i in entry.credential_ids if i not in credential_ids]
        if unknown or len(set(entry.credential_ids)) != len(entry.credential_ids):
            raise ValueError("transaction_data entry %d: credential_ids %s must name this "
                             "request's credential queries (%s), each once"
                             % (position, list(entry.credential_ids), ", ".join(credential_ids)))
        if entry.is_ts12 and not isinstance(entry.document.get("payload"), dict):
            raise ValueError("transaction_data entry %d is of the TS12 type %s and carries no "
                             "payload object (TS12 section 4.2)" % (position, entry.type))
        if entry.type == TS12_PAYMENT:
            problems = ts12_payment_problems(entry.document["payload"])
            if problems:
                raise ValueError("transaction_data entry %d is a TS12 payment whose payload does "
                                 "not satisfy TS12's schema: %s" % (position, "; ".join(problems)))
        out.append(entry)
    shared = set(TRANSACTION_DATA_HASH_ALGS)
    for entry in out:
        shared &= entry.allowed_algs()
    if not shared:
        raise ValueError("the transaction_data entries share no hash algorithm this verifier "
                         "computes, so no key binding JWT could hash them all")
    return tuple(out)


def claim_query(claim):
    """One claim the DCQL query asks for, as `(path, values)`.

    A claim is a name (`"given_name"`), a path of object keys (`["age_equal_or_over", "18"]`:
    the EUDI PID Rulebook nests its age statements, so asking for `age_equal_or_over` alone
    asks the wallet for every age statement at once), or a DCQL claim object
    `{"path": [...], "values": [...]}`, whose `values` the disclosed value must match.

    Array indices and the null wildcard are refused: an undisclosed array element is left out
    of the disclosed claims, so a position counted after disclosure is not the position the
    issuer signed, and a verifier that checked it would check the wrong element.
    """
    if isinstance(claim, str):
        path, values = [claim], None
    elif isinstance(claim, dict):
        unknown = sorted(set(claim) - {"path", "values"})
        if unknown:
            raise ValueError("a claim object has `path` and `values` only, not %s" % ", ".join(unknown))
        path, values = claim.get("path"), claim.get("values")
    elif isinstance(claim, (list, tuple)):
        path, values = list(claim), None
    else:
        raise ValueError("a claim is a name, a path or a DCQL claim object: %r" % (claim,))
    if not isinstance(path, list) or not path or not all(isinstance(k, str) and k for k in path):
        raise ValueError("a claim's path is one or more object keys (non-empty strings); array "
                         "indices and null are not supported: %r" % (claim,))
    # bool is an int in Python, which is what DCQL allows: strings, integers and booleans.
    if values is not None and (not isinstance(values, list) or not values
                               or not all(isinstance(v, (str, int)) for v in values)):
        raise ValueError("a claim's values are a non-empty list of strings, integers or "
                         "booleans: %r" % (claim,))
    return tuple(path), (tuple(values) if values is not None else None)


def disclosed_at(claims, path):
    """`(True, value)` when the disclosed claims hold `path`, key by key; else `(False, None)`."""
    node = claims
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return False, None
        node = node[key]
    return True, node


def value_matches(value, values):
    """DCQL `values`: the type and the value both match one of them, so `true` is not `1`."""
    return any(type(value) is type(v) and value == v for v in values)


def _shown(path):
    return repr(".".join(str(key) for key in path))


def _selected(path, requested):
    """Whether a disclosed claim at `path` is one the request selected (OpenID4VP 1.0 6.4).

    It is when it lies on the way to a requested path (the object a requested member is
    reached through) or inside one (a member of a requested object or array).
    """
    return any(path == r[:len(path)] or r == path[:len(r)] for r in requested)


class Session:
    """One outstanding presentation request, and the secrets that make it answerable once."""

    __slots__ = ("state", "nonce", "enc_key", "created", "answered", "transaction_data")

    def __init__(self, enc_key, transaction_data=()):
        self.state = secrets.token_urlsafe(16)
        # 256 bits. OpenID4VP 1.0 section 5.2 requires "sufficient entropy" and the suite
        # warns below 128 bits, which is a floor rather than a target.
        self.nonce = secrets.token_urlsafe(32)
        self.enc_key = enc_key
        self.created = time.time()
        self.answered = False
        # This request's transaction_data entries (TransactionDataEntry), empty for none.
        self.transaction_data = tuple(transaction_data)



def verifier_info_entries(entries, credential_ids=()):
    """`verifier_info` for the request object, checked against OpenID4VP 1.0 section 5.1.

    A non-empty array of attestations about the verifier: each an object with `format` (a
    string, such as "registration_cert" for the registration certificate a registrar issues)
    and `data` (a string or an object), and optionally `credential_ids`, the credential queries
    it applies to. The German EUDI Wallet ecosystem requires one for a PID request, and its
    verifier testing tool, ERICA, refuses a request without it (2026-10-04). ERICA and the German
    developer guide read a single object, `verifier_info.data`, where section 5.1 has an array,
    so a single object is carried as a single object: the operator supplies the shape its
    ecosystem reads. This package does not issue or check the attestation; it carries what the
    operator was given. Anything else is refused here, at construction, rather than sent, and
    so is a registration certificate labelled with its own media type (_registration_cert_labels).
    `check_etsi_119472_2` holds it to ETSI TS 119 472-2 when the verifier selects that profile.
    """
    _registration_cert_labels(entries)
    if isinstance(entries, dict):
        return verifier_info_entries([entries], credential_ids)[0]
    if not isinstance(entries, list) or not entries:
        raise ValueError("verifier_info must be a JSON object or a non-empty JSON array of them")
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each verifier_info entry must be a JSON object, not %r" % (entry,))
        unknown = set(entry) - {"format", "data", "credential_ids"}
        if unknown:
            raise ValueError("verifier_info entry has unknown member(s) %s"
                             % ", ".join(sorted(map(str, unknown))))
        if not isinstance(entry.get("format"), str) or not entry["format"]:
            raise ValueError("each verifier_info entry needs a non-empty string format")
        if not isinstance(entry.get("data"), (str, dict)) or entry["data"] in ("", {}):
            raise ValueError("each verifier_info entry needs data: a string or an object")
        ids = entry.get("credential_ids")
        if ids is not None and (not isinstance(ids, list) or not ids
                                or not all(isinstance(i, str) and i in credential_ids
                                           for i in ids)):
            raise ValueError("verifier_info credential_ids must be a non-empty array naming "
                             "this request's credential queries (%s)" % ", ".join(credential_ids))
        out.append(json.loads(json.dumps(entry)))
    return out


# ------------------------------------------------- verifier_info under ETSI TS 119 472-2

#: The verifier_info profile `Verifier(verifier_info_profile=...)` and `serve
#: --verifier-info-profile` select: ETSI TS 119 472-2 V1.2.1 (2026-03), whose HAIP-common request
#: object requires verifier_info (OIDFVP-HAIP-COMMON-REQ-RO-01 to -16). Opt-in: without a profile
#: verifier_info is held to OpenID4VP 1.0 section 5.1 alone (OPTIONAL, a non-empty array), and the
#: request object is the one it always was.
ETSI_119472_2 = "etsi-119472-2"
VERIFIER_INFO_PROFILES = (ETSI_119472_2,)

#: ETSI TS 119 475's media types for a registration certificate, the JWT's and the CWT's.
_REGISTRATION_CERT_TYPS = {"rc-wrp+jwt": "JWT", "rc-wrp+cwt": "CWT"}

#: RFC 3986 section 4.3, absolute-URI: a scheme, ":", then the hier-part and an optional query,
#: and no fragment. Each character is one RFC 3986 allows, "%" only begins a percent-encoded
#: octet, and something follows the ":".
_ABSOLUTE_URI = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~!$&'()*+,;=:@/?\[\]-]|%[0-9A-Fa-f]{2})+")

_MISSING = object()


class VerifierInfoError(ValueError):
    """verifier_info refused at construction, so no request carrying it is ever made. The
    message names the requirement it fails."""


def _etsi_refusal(numbers, reason):
    """A refusal naming the ETSI TS 119 472-2 V1.2.1 requirements it fails by their IDs."""
    return VerifierInfoError("verifier_info fails ETSI TS 119 472-2 V1.2.1 %s: %s" % (
        " and ".join("OIDFVP-HAIP-COMMON-REQ-RO-%02d" % n for n in numbers), reason))


def _over_asking_refusal(reason):
    """A refusal by the over-asking check (_within_registration), saying what it read."""
    return VerifierInfoError(
        "verifier_info: the over-asking check refuses this request: %s. A wallet that enforces "
        "the registration certificate refuses a request asking for more than it registers. (The "
        "certificate's payload is read for this; its signature is NOT checked.)" % reason)


def _given(value):
    """How a refusal shows the value it was given: "absent", or the value as JSON, cut short."""
    if value is _MISSING:
        return "absent"
    text = json.dumps(value, ensure_ascii=False, default=repr)
    return text if len(text) <= 60 else text[:57] + "..."


def _nonempty_string(value):
    return isinstance(value, str) and bool(value)


def _media_type(value):
    """A media type as RFC 7515 section 4.1.9 compares one: case-insensitively, with
    "application/" understood where it is left out."""
    value = value.strip().lower()
    return value[len("application/"):] if value.startswith("application/") else value


def _compact_jws_parts(data):
    """The three parts of the JWS compact serialization `data` holds, read either way RO-16's
    "the base64url encoding of the serialized RP registration certificate" can be read: the
    compact serialization as it is (its parts are base64url already), or that serialization
    base64url-encoded once more, which must decode to ASCII. None when it is neither."""
    if not isinstance(data, str):
        return None
    parts = data.split(".")
    if len(parts) == 3:
        return parts
    try:
        parts = b64u_decode(data).decode("ascii").split(".")
    except ValueError:
        return None
    return parts if len(parts) == 3 else None


def _jws_typ(data):
    """The `typ` in the header of `data` read as a JWS compact serialization (_compact_jws_parts),
    or None when it is not one. Only the header is read; no signature is checked."""
    parts = _compact_jws_parts(data)
    if parts is None:
        return None
    try:
        header = _loads_depth_bounded(b64u_decode(parts[0]), "JWS header")
    except ValueError:
        return None
    typ = header.get("typ") if isinstance(header, dict) else None
    return _media_type(typ) if isinstance(typ, str) else None


def _registration_cert_labels(verifier_info):
    """The label check, profile or none: a registration certificate carried under its own media
    type, as a format or in a JWS header, instead of the format RO-15 gives it. The German EUDI
    Wallet's iOS issue #38, "WRPRC policy is configured but no WRPRC found in verifier_info", is
    this mistake. ETSI TS 119 472-2 RO-15 and the German developer guide both say
    "registration_cert", so refusing either label changes no correct request."""
    entries = verifier_info if isinstance(verifier_info, list) else [verifier_info]
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("format"), str):
            continue
        where = "entry %d" % position if isinstance(verifier_info, list) else "the entry"
        typ = _media_type(entry["format"])
        # RO-15: the registration certificate's verifier_info format is registration_cert, and
        # rc-wrp+jwt / rc-wrp+cwt are its JWT and CWT typ (ETSI TS 119 475), never that format.
        if typ in _REGISTRATION_CERT_TYPS:
            raise _etsi_refusal((15,), "%s has format %r: %s is the registration certificate's %s "
                                       "typ (ETSI TS 119 475); its verifier_info format is "
                                       "registration_cert (ETSI TS 119 472-2 RO-15)"
                                % (where, entry["format"], typ, _REGISTRATION_CERT_TYPS[typ]))
        # RO-15: a JWS typed rc-wrp+jwt IS a registration certificate, under whatever label.
        if entry["format"] != "registration_cert" and _jws_typ(entry.get("data")) == "rc-wrp+jwt":
            raise _etsi_refusal((15,), "%s has format %r and its data is a JWS typed rc-wrp+jwt, a "
                                       "registration certificate (ETSI TS 119 475); its "
                                       "verifier_info format is registration_cert (ETSI TS 119 "
                                       "472-2 RO-15)" % (where, entry["format"]))


def _names_a_registration_cert(label):
    """Whether a verifier_info format names a registration certificate: RO-15's own words in
    another case or spelling ("Registration-Cert", "registration_certificate"), or TS 119 475's
    names for one ("WRPRC", "rc-wrp")."""
    folded = re.sub(r"[^a-z0-9]", "", label.lower())
    return folded.startswith(("registrationcert", "wrprc", "rcwrp"))


def _absolute_uri(value):
    return isinstance(value, str) and _ABSOLUTE_URI.fullmatch(value) is not None


def _identifiers(value):
    """A non-empty array of ETSI TS 119 475 B.2.5 Class Identifier objects: each a `type` and an
    `identifier`, both [1..1] string, and neither empty."""
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, dict) and _nonempty_string(item.get("type"))
                    and _nonempty_string(item.get("identifier")) for item in value))


def _multilang_strings(value):
    """A non-empty array of ETSI TS 119 475 Class MultiLangString objects: each a `lang` and a
    `content`, both non-empty strings."""
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, dict) and _nonempty_string(item.get("lang"))
                    and _nonempty_string(item.get("content")) for item in value))


def _meta_within(asked, registered):
    """Whether a credential query's `meta` asks for nothing a registered credential's `meta`
    does not allow. Each member the certificate states, the query states too and keeps inside it:
    a list to a subset of the certificate's, any other value to the same value. A credential that
    states no meta restricts none, as one with no `claim` restricts no claim."""
    if registered is _MISSING:
        return True
    if not isinstance(asked, dict):
        return False
    for name, allowed in registered.items():
        if name not in asked:
            return False
        if isinstance(allowed, list):
            if not isinstance(asked[name], list) or any(v not in allowed for v in asked[name]):
                return False
        elif asked[name] != allowed:
            return False
    return True


def _within_registration(certificate, dcql_query):
    """The over-asking check: the request's DCQL query asks for no credential, and no claim
    path, that the registration certificate does not register. The German EUDI Wallet refuses
    such a request: iOS 0.3.9, "Presentation requests are refused when the relying party is
    asking more than what was registered in the registration certificate"; Android #40, "the
    registration cert credentials object has the same structure as the DCQL, so it has to be
    identical". This checks this verifier's own request. It judges no wallet's.

    The certificate's payload is read WITHOUT checking its signature: it is the operator's own
    certificate, read only to hold the operator's own request to it. What it registers is its
    `credentials`, each ETSI TS 119 475's Class Credential: a `format`, a `meta`, and "claim
    [0..*] Claim", each claim with a `path`. A credential query is registered by one credential
    of the same format whose meta allows the query's (_meta_within) and which registers each
    claim path the query asks for, exactly, as the Android wallet compares them; `values` are
    not compared. TS 119 475: "If claim is absent, the WRPRC does not declare any specific
    attributes intended to be requested by the WRP", so a credential without `claim` is held
    to its format and meta only. The certificate is read in either form RO-16 allows
    (_compact_jws_parts). One this cannot read registers nothing it can rely on, and is refused
    rather than passed.
    """
    parts = _compact_jws_parts(certificate)
    payload = None
    if parts is not None:
        try:
            payload = _loads_depth_bounded(b64u_decode(parts[1]),
                                           "registration certificate payload")
        except ValueError:
            payload = None
    if not isinstance(payload, dict):
        raise _over_asking_refusal("the registration certificate is not a JWT this check can "
                                   "read, a JWS compact serialization as it is or base64url-"
                                   "encoded once more, with a JSON object payload; so what it "
                                   "registers cannot be read")
    registered = payload.get("credentials", _MISSING)
    if not isinstance(registered, list) or not registered:
        raise _over_asking_refusal("the registration certificate's credentials are %s, so it "
                                   "registers no credential to ask for" % _given(registered))
    for position, credential in enumerate(registered):
        if not isinstance(credential, dict):
            raise _over_asking_refusal("the registration certificate's credentials[%d] is %s, "
                                       "not an object" % (position, _given(credential)))
        # The certificate's key is `claim` (TS 119 475, "claim [0..*] Claim"); the DCQL's is
        # `claims`. A certificate using `claims` is not read as registering no claim.
        if "claims" in credential:
            raise _over_asking_refusal("the registration certificate's credentials[%d] has "
                                       "`claims`, which is not ETSI's key: ETSI TS 119 475's "
                                       "Class Credential names it `claim`" % position)
        claim = credential.get("claim", _MISSING)
        if claim is not _MISSING and not (isinstance(claim, list) and all(
                isinstance(c, dict) and isinstance(c.get("path"), list) for c in claim)):
            raise _over_asking_refusal("the registration certificate's credentials[%d].claim is "
                                       "%s, not an array of claims each with a path"
                                       % (position, _given(claim)))
        if "meta" in credential and not isinstance(credential["meta"], dict):
            raise _over_asking_refusal("the registration certificate's credentials[%d].meta is "
                                       "%s, not an object" % (position, _given(credential["meta"])))
    for query in dcql_query["credentials"]:
        matching = [c for c in registered if c.get("format") == query.get("format")
                    and _meta_within(query.get("meta"), c.get("meta", _MISSING))]
        if not matching:
            raise _over_asking_refusal("credential query %r asks for format %s with meta %s, and "
                                       "none of the certificate's credentials registers that"
                                       % (query.get("id"), _given(query.get("format")),
                                          _given(query.get("meta"))))
        asked = [list(c["path"]) for c in query.get("claims", [])]

        def unregistered(credential):
            if "claim" not in credential:
                return []
            paths = [list(c["path"]) for c in credential["claim"]]
            return [path for path in asked if path not in paths]

        gaps = min((unregistered(c) for c in matching), key=len)
        if gaps:
            raise _over_asking_refusal("credential query %r asks for the claim path %s, which the "
                                       "certificate's credential of that type does not register"
                                       % (query.get("id"), ", ".join(_given(p) for p in gaps)))


def check_etsi_119472_2(verifier_info, dcql_query):
    """Hold verifier_info, before any request carries it, to ETSI TS 119 472-2 V1.2.1's
    requirements for the HAIP-common request object (OIDFVP-HAIP-COMMON-REQ-RO-01 to -16), and
    the request's `dcql_query` to the registration certificate it carries (_within_registration).
    Returns whether that over-asking check ran, which it does when verifier_info carries a
    registration certificate; raises VerifierInfoError naming the requirement it fails.

    Shape and labels only. The registration certificate's signature, its chain and the
    registrar's data are NOT validated, here or anywhere in this package: the certificate's
    payload is read, unverified, only to hold this verifier's own request to it. RO-16 has the
    certificate element's data be "the base64url encoding of the serialized RP registration
    certificate", which leaves open whether a JWT goes as its compact serialization (the EU
    reference verifier's README: "serialized using JWS Compact Serialization"; EUDIPLO sends the
    JWT string as is) or encoded once more. RO-16 is therefore checked as any non-empty string,
    and the over-asking check, which must read the certificate, reads either form.
    """
    _registration_cert_labels(verifier_info)
    # RO-01: "The RO JWT body shall contain the verifier_info parameter." An empty array carries
    # none of it, and OpenID4VP 1.0 section 5.1 has the parameter a non-empty array.
    if verifier_info is None or verifier_info == []:
        raise _etsi_refusal((1,), "the request carries no verifier_info" if verifier_info is None
                            else "verifier_info is an empty array")
    # RO-03 and RO-14 speak of "the element in the verifier_info array": under this profile it is
    # an array. A single object, as the German developer guide shows, is carried outside it.
    if not isinstance(verifier_info, list):
        raise _etsi_refusal((3, 14), "verifier_info is %s, not an array of elements" % (
            "a single object" if isinstance(verifier_info, dict) else _given(verifier_info)))
    # Each element is a JSON object, as RO-03 and RO-14's elements are, and OpenID4VP 1.0
    # section 5.1's: a string beside them is no element.
    for position, element in enumerate(verifier_info):
        if not isinstance(element, dict):
            raise _etsi_refusal((3, 14), "verifier_info element %d is %s, not an object"
                                % (position, _given(element)))
    elements = [e for e in verifier_info if isinstance(e, dict)]
    # RO-02 and RO-04: one element, with format registrar_dataset, carries the registrar's data.
    registrars = [e for e in elements if e.get("format") == "registrar_dataset"]
    if len(registrars) != 1:
        raise _etsi_refusal((2, 4), "verifier_info has %d elements with format registrar_dataset, "
                                    "where it carries exactly one" % len(registrars))
    registrar = registrars[0]
    # RO-03: the registrar_dataset element carries no credential_ids.
    if "credential_ids" in registrar:
        raise _etsi_refusal((3,), "the registrar_dataset element carries credential_ids")
    data = registrar.get("data", _MISSING)
    # RO-05: its data is a JSON object, and a non-empty one.
    if not isinstance(data, dict) or not data:
        raise _etsi_refusal((5,), "the registrar_dataset element's data is %s, not a non-empty "
                                  "JSON object" % _given(data))
    # RO-06: identifier, Class Identifier objects (ETSI TS 119 475 B.2.5).
    if not _identifiers(data.get("identifier", _MISSING)):
        raise _etsi_refusal((6,), "data.identifier is %s, not a non-empty array of objects each "
                                  "with a non-empty string type and identifier"
                            % _given(data.get("identifier", _MISSING)))
    # RO-07: srvDescription, Class MultiLangString objects (ETSI TS 119 475).
    if not _multilang_strings(data.get("srvDescription", _MISSING)):
        raise _etsi_refusal((7,), "data.srvDescription is %s, not a non-empty array of "
                                  "MultiLangString objects (a non-empty string lang and content)"
                            % _given(data.get("srvDescription", _MISSING)))
    # RO-08: registryURI, an absolute URI.
    if not _absolute_uri(data.get("registryURI", _MISSING)):
        raise _etsi_refusal((8,), "data.registryURI is %s, not an absolute URI (RFC 3986 section "
                                  "4.3)" % _given(data.get("registryURI", _MISSING)))
    # RO-09: intendedUseIdentifier, a non-empty string.
    if not _nonempty_string(data.get("intendedUseIdentifier", _MISSING)):
        raise _etsi_refusal((9,), "data.intendedUseIdentifier is %s, not a non-empty string"
                            % _given(data.get("intendedUseIdentifier", _MISSING)))
    # RO-10: purpose, Class MultiLangString objects.
    if not _multilang_strings(data.get("purpose", _MISSING)):
        raise _etsi_refusal((10,), "data.purpose is %s, not a non-empty array of MultiLangString "
                                   "objects (a non-empty string lang and content)"
                            % _given(data.get("purpose", _MISSING)))
    # RO-11: policyURI, an absolute URI.
    if not _absolute_uri(data.get("policyURI", _MISSING)):
        raise _etsi_refusal((11,), "data.policyURI is %s, not an absolute URI (RFC 3986 section "
                                   "4.3)" % _given(data.get("policyURI", _MISSING)))
    # RO-12: data "May contain" credential; when it does, a non-empty array of objects.
    credential = data.get("credential", _MISSING)
    if credential is not _MISSING and not (isinstance(credential, list) and credential and all(
            isinstance(c, dict) for c in credential)):
        raise _etsi_refusal((12,), "data.credential is %s, not a non-empty array of objects"
                            % _given(credential))
    # RO-13 and RO-15: an element carrying the registration certificate has RO-15's format,
    # registration_cert; one whose format names a certificate otherwise is mislabelled. (One
    # labelled with the certificate's own typ was refused above, in every mode.)
    for position, element in enumerate(verifier_info):
        label = element.get("format") if isinstance(element, dict) else None
        if (isinstance(label, str) and label != "registration_cert"
                and _names_a_registration_cert(label)):
            raise _etsi_refusal((13, 15), "element %d has format %r, which names a registration "
                                          "certificate; its verifier_info format is "
                                          "registration_cert" % (position, label))
    certificates = [e for e in elements if e.get("format") == "registration_cert"]
    # At most one registration certificate, on three grounds: RO-13 provides for "a" registration
    # certificate; "two separately issued certificates cannot be combined" (Mibuw's
    # miEUDIverifier, Apache-2.0); and the German wallet's registration certificate policy.
    if len(certificates) > 1:
        raise _etsi_refusal((13,), "verifier_info has %d registration_cert elements; a request "
                                   "carries at most one registration certificate, since two "
                                   "separately issued certificates cannot be combined"
                            % len(certificates))
    for certificate in certificates:
        # RO-14: the registration certificate's element carries no credential_ids.
        if "credential_ids" in certificate:
            raise _etsi_refusal((14,), "the registration_cert element carries credential_ids")
        # RO-16: its data is the certificate, serialized and base64url-encoded: a string, and
        # not an empty one. Any non-empty string passes here (see above).
        cert_data = certificate.get("data", _MISSING)
        if not _nonempty_string(cert_data):
            raise _etsi_refusal((16,), "the registration_cert element's data is %s, not a "
                                       "non-empty string" % _given(cert_data))
        _within_registration(cert_data, dcql_query)
    return bool(certificates)


def request_object_encryption(wallet_metadata):
    """Where to encrypt the request object for a wallet that asked, or None.

    OpenID4VP 1.0 section 5.10: a wallet that requires the request object encrypted passes its
    public encryption keys as `jwks` in `wallet_metadata`, beside the algorithms it can open,
    `request_object_encryption_alg_values_supported` and `..._enc_values_supported`. The EUDI
    iOS wallet kit (0.54.5) always asks, ECDH-ES with A128GCM on P-256, and refuses a request
    object that is not encrypted (lab/interop/eudi-ios, 2026-10-04).

    Returns (public_key, enc, kid) when the wallet names ECDH-ES, an `enc` this package can
    produce (A128GCM or A256GCM, the wallet's order) and a P-256 key that is not marked for
    another use or algorithm. Otherwise None, and the signed object is served as it always
    was: to a wallet that asked for nothing, to one asking for what this cannot produce, and to
    metadata that does not parse, because the verifier MUST ignore what it does not recognise.
    The key is the wallet's to name; the object is public and signed, so encrypting it to
    whoever asks gives them nothing an unencrypted fetch would not.
    """
    if isinstance(wallet_metadata, (str, bytes, bytearray)):
        try:
            wallet_metadata = _loads_depth_bounded(wallet_metadata, "wallet_metadata")
        except ValueError:
            return None
    if not isinstance(wallet_metadata, dict):
        return None
    algs = wallet_metadata.get("request_object_encryption_alg_values_supported")
    encs = wallet_metadata.get("request_object_encryption_enc_values_supported")
    if not isinstance(algs, list) or ACCEPTED_ALG not in algs or not isinstance(encs, list):
        return None
    enc = next((e for e in encs if isinstance(e, str) and e in ACCEPTED_ENC), None)
    jwks = wallet_metadata.get("jwks")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if enc is None or not isinstance(keys, list):
        return None
    for jwk in keys:
        if (not isinstance(jwk, dict) or jwk.get("use", "enc") != "enc"
                or jwk.get("alg", ACCEPTED_ALG) != ACCEPTED_ALG):
            continue
        try:
            public_key = _public_key_from_jwk(jwk)
        except JweError:
            continue
        kid = jwk.get("kid")
        return public_key, enc, kid if isinstance(kid, str) else None
    return None


def _form_values(form, name):
    """Every value a posted form gives `name`: `urllib.parse.parse_qs` makes a list, and a
    framework that keeps one value per name, a string. A blank value is no value, as parse_qs
    has it."""
    value = form.get(name)
    values = list(value) if isinstance(value, (list, tuple)) else [value]
    return [v for v in values if v is not None and v != ""]


def _printable(text, limit=ERROR_DESCRIPTION_MAX):
    """`text` as an operator's terminal and log may show it. The characters RFC 6749 allows an
    `error_description` (%x20-21 / %x23-5B / %x5D-7E) are kept, except `<`; anything else, a
    control byte, the ESC that starts a terminal escape sequence, a line break, a quote, a
    letter outside ASCII, becomes `?`, and so does `<`: `serve` prints each answer as
    `<- STATUS ...`, and text that could carry `<-` could read as another answer to a grep. It
    is cut to `limit` characters."""
    kept = "".join(ch if " " <= ch <= "~" and ch not in "\"\\<" else "?"
                   for ch in text[:limit + 1])
    return kept if len(kept) <= limit else kept[:limit - 3] + "..."


class Verifier:
    """Builds requests and judges responses. Holds no socket: see `serve()` for that.

    Split this way so the decision path can be tested without a network, which is also how
    the seven refusals get regression tests that do not need the conformance suite running.
    """

    def __init__(self, *, client_cert_pem, client_key_pem, request_uri, response_uri,
                 issuer_jwks=None, issuer_trust_anchors=None, redirect_uri=None,
                 request_ttl_seconds=DEFAULT_REQUEST_TTL_SECONDS,
                 vct_values=("urn:eudi:pid:1",), claims=("given_name", "family_name"),
                 status_resolver=None, verifier_info=None, credential_query_id=None,
                 verifier_info_profile=None, redirect=True):
        if not _HAVE_CRYPTO:
            raise RuntimeError("polaris-oid4vp requires the cryptography package")
        # The id of the request's one DCQL credential query, "pid" unless named. A
        # transaction_data entry names it in credential_ids, and the published TS12 vectors
        # name "pay" inside the very string that is hashed, so it cannot be rewritten to fit.
        self.query_id = self.DCQL_QUERY_ID if credential_query_id is None else credential_query_id
        if not isinstance(self.query_id, str) or not _DCQL_ID.fullmatch(self.query_id):
            raise ValueError("a credential query id is a non-empty string of letters, digits, _ "
                             "and - (OpenID4VP 1.0 section 6.1), not %r" % (self.query_id,))
        self.cert = load_pem_x509_certificate(client_cert_pem)
        self.key = serialization.load_pem_private_key(client_key_pem, password=None)
        der = self.cert.public_bytes(serialization.Encoding.DER)
        # x509_hash: the client identifier IS the leaf's digest, so the wallet can tie the
        # request object's signing certificate to the identifier without a directory.
        self.client_id = "x509_hash:" + b64u_encode(_sha256(der))
        self.x5c = [base64.b64encode(der).decode("ascii")]
        self.request_uri = request_uri
        self.response_uri = response_uri
        self.redirect_uri = redirect_uri or (response_uri.rsplit("/", 1)[0] + "/done")
        # Whether an accepted response is answered with a redirect_uri at all. OpenID4VP 1.0
        # section 8.2 makes it OPTIONAL. A cross-device flow whose screen learns the result by
        # polling has nobody to send there, so `redirect=False` answers `{}` and issues no
        # response_code that nobody would redeem.
        self.redirect = bool(redirect)
        self.issuer_jwks = list(issuer_jwks or [])
        self.issuer_trust_anchors = list(issuer_trust_anchors or [])
        self.request_ttl_seconds = request_ttl_seconds
        self.vct_values = list(vct_values)
        self.claims = [claim_query(c) for c in claims]
        # Revocation. None means the verdict reports `not_evaluated`, which is what this
        # verifier can honestly say about a status list nobody read. Threaded from here
        # rather than left on `verify_presentation` alone because THIS is the surface an
        # operator uses: the class that answers the wallet. A parameter reachable only from
        # the function underneath it is a capability the product does not have.
        self.status_resolver = status_resolver
        # A profile the verifier_info is held to before any request carries it. An unknown name
        # is refused: one misspelt would otherwise check nothing and say nothing.
        if verifier_info_profile is not None and verifier_info_profile not in VERIFIER_INFO_PROFILES:
            raise VerifierInfoError("verifier_info_profile %r is not a profile this verifier knows "
                                    "(%s)" % (verifier_info_profile, ", ".join(VERIFIER_INFO_PROFILES)))
        self.verifier_info_profile = verifier_info_profile
        # Whether the request was held to a registration certificate's credentials: under the
        # profile, when verifier_info carries one. Never claimed otherwise.
        self.over_asking_checked = False
        if verifier_info_profile == ETSI_119472_2:
            self.over_asking_checked = check_etsi_119472_2(verifier_info, self._dcql_query())
        self.verifier_info = (None if verifier_info is None
                              else verifier_info_entries(verifier_info, (self.query_id,)))
        self._sessions = {}
        self._by_request = {}
        # Accepted responses waiting to be fetched with their response_code (`redeem`), keyed by
        # the code's SHA-256 so the lookup compares no secret: digest -> (when, state, verdict).
        self._results = {}
        self._lock = threading.Lock()
        self._jti_memory = JtiMemory(retention_seconds=JTI_RETENTION_SECONDS)

    # ------------------------------------------------------------------ the request

    def new_request(self, transaction_data=None):
        """Start one presentation request. Returns (session, the signed request object).

        `transaction_data`, opt-in per request, is the entries this request asks the wallet to
        authorize (OpenID4VP 1.0 section 8.4), as `transaction_data_entries` takes them; an entry
        a wallet would refuse raises ValueError here and no request is made. The request object
        carries them, and the presentation's key binding JWT must bind every one: with one
        credential query, every entry names it, so both readings of which entries a key binding
        JWT binds expect all of them. Without it the request is exactly what it always was.
        """
        entries = (() if transaction_data is None
                   else transaction_data_entries(transaction_data, (self.query_id,)))
        enc_key = ec.generate_private_key(ec.SECP256R1())
        session = Session(enc_key, entries)
        jar = self._request_object(session)
        with self._lock:
            self._expire_locked()
            self._sessions[session.state] = session
            self._by_request[session.state] = jar
        return session, jar

    def request_object(self, state, wallet_nonce=None, wallet_metadata=None):
        """The JAR for an outstanding request, served as many times as it is asked for.

        The plan has a module that fetches the `request_uri` TWICE. Making a request object
        single-use would look like prudence and would fail it, and would fail nothing real:
        the object is signed, public, and carries its own expiry.

        `wallet_nonce` is the other half of `request_uri_method=post`. OpenID4VP 1.0 section
        5.10: when a wallet POSTs one, the verifier MUST return a request object carrying it
        as a top-level claim. It is the wallet's replay protection against a request object
        minted before the wallet existed, and the mirror of the `nonce` we send it, so a
        verifier that serves a cached object to a POST has taken that protection away.

        `wallet_metadata`, posted beside it, may ask for the object encrypted to the wallet's
        key (`request_object_encryption`). Then the same signed object comes back encrypted:
        a signed-then-encrypted nested JWT, as RFC 9101 section 6.1 has it.
        """
        # An outstanding request only: a session past its lifetime is gone, and neither its cached
        # object nor a fresh one minted for a wallet nonce is served. Until 2026-10-01 this path
        # never expired anything, so an hour-old request was re-signed with a new `exp`.
        with self._lock:
            self._expire_locked()
            session = self._sessions.get(state)
            cached = self._by_request.get(state)
        if wallet_nonce is None:
            jar = cached
        elif session is None:
            return None
        else:
            jar = self._request_object(session, wallet_nonce=wallet_nonce)
        target = None if jar is None else request_object_encryption(wallet_metadata)
        if target is None:
            return jar
        public_key, enc, kid = target
        header = {"cty": "JWT"}
        if kid is not None:
            header["kid"] = kid
        return encrypt_compact(jar.encode("ascii"), public_key, enc, extra_header=header)

    def _request_object(self, session, wallet_nonce=None):
        numbers = session.enc_key.public_key().public_numbers()
        enc_jwk = {"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
                   "kid": "enc-" + session.state,
                   "x": b64u_encode(numbers.x.to_bytes(32, "big")),
                   "y": b64u_encode(numbers.y.to_bytes(32, "big"))}
        now = int(time.time())
        claims = {
            "iss": self.client_id,
            "aud": WALLET_AUDIENCE,
            "client_id": self.client_id,
            "response_type": "vp_token",
            "response_mode": RESPONSE_MODE,
            "response_uri": self.response_uri,
            "nonce": session.nonce,
            "state": session.state,
            "iat": now,
            "exp": now + self.request_ttl_seconds,
            # Exactly three keys. The suite warns on a fourth and fails on the older
            # authorization_encrypted_response_alg/_enc names, which an earlier draft used.
            "client_metadata": {
                "jwks": {"keys": [enc_jwk]},
                "vp_formats_supported": {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"],
                                                       "kb-jwt_alg_values": ["ES256"]}},
                "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
            },
            "dcql_query": self._dcql_query(),
        }
        if session.transaction_data:
            # The strings exactly as they will be hashed: never re-encoded after this point.
            claims["transaction_data"] = [entry.raw for entry in session.transaction_data]
        if wallet_nonce is not None:
            claims["wallet_nonce"] = wallet_nonce
        if self.verifier_info:
            claims["verifier_info"] = self.verifier_info
        header = {"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": self.x5c}
        return _sign_es256(self.key, header, claims)

    def _dcql_query(self):
        """The DCQL query every request object carries, one credential query. Built in one place
        so the over-asking check holds the registration certificate to the query that is sent."""
        return {"credentials": [{
            "id": self.query_id,
            "format": "dc+sd-jwt",
            "meta": {"vct_values": self.vct_values},
            "claims": [dict({"path": list(path)}, **({"values": list(values)} if values else {}))
                       for path, values in self.claims],
        }]}

    def authorization_request_params(self, session):
        """What goes in the query string the wallet is launched with.

        `request_uri_method=post` is advertised because it is strictly better for the wallet:
        it lets the wallet contribute a nonce to the request object. It is also the parameter
        a conformance module looks for before it will run at all, and a module that SKIPS is
        not a module that passed, which is a distinction worth one line of query string.
        """
        return {"client_id": self.client_id,
                "request_uri": "%s?state=%s" % (self.request_uri, session.state),
                "request_uri_method": "post"}

    # ----------------------------------------------------------------- the response

    def handle_direct_post(self, form):
        """Judge one `direct_post.jwt` response. Returns (http_status, body_dict, verdict).

        200 with only a `redirect_uri` when the presentation is authentic, 400 with an OAuth
        error otherwise. Nothing returns 500: every way this can go wrong is the response
        being unacceptable, and a 5xx would tell the wallet to retry something that will
        never work.

        One exception to the 400: a wallet's Authorization Error Response (OpenID4VP 1.0
        section 8.5) naming an outstanding request is processed, and section 8.2 answers a
        processed one "with an HTTP status code of 200 with Content-Type of application/json and
        a JSON object in the response body". The object is `{}`: no `redirect_uri`, because the
        page it leads to says the presentation is complete. The verdict is never authentic and
        carries no claims; its code is `wallet_error`, and `verdict.wallet_error` holds what the
        response said. So a 200 is not an acceptance. `verdict.authentic` is. Neither form of
        it, encrypted or in the clear, closes the request: anyone who saw the request could
        have sent either.
        """
        # An error response sent in the clear: `error` and `state` as form parameters, where a
        # wallet that can encrypt sends `response` (section 8.3.1).
        if _form_values(form, "error"):
            return self._error_in_the_clear(form)
        token = (form.get("response") or [""])[0] if isinstance(form.get("response"), list) \
            else form.get("response") or ""
        if not token:
            return self._error("invalid_request", "no 'response' parameter was posted")

        session, body = None, None
        # The response is encrypted to a PER-REQUEST key, so finding the session means
        # finding the key that opens it. Trying each outstanding one is deliberate: the
        # `state` that would let us look it up directly is INSIDE the ciphertext, and
        # trusting an unauthenticated state parameter to pick a decryption key is how a
        # verifier gets steered onto the wrong session.
        with self._lock:
            self._expire_locked()
            candidates = list(self._sessions.values())
        for candidate in candidates:
            try:
                body = decrypt_response(token, candidate.enc_key)
            except JweError:
                continue
            session = candidate
            break
        if session is None:
            return self._error("invalid_request",
                               "the response did not decrypt under any outstanding "
                               "request's key: it was encrypted to somebody else, altered, "
                               "or it answers a request that has expired")

        if body.get("state") != session.state:
            return self._error("invalid_request",
                               "the response's state does not match the request its "
                               "encryption key belongs to")

        # An error response encrypted to this request's key is answered as the same response in
        # the clear is: 200, recorded, and the request left open, before anything below can
        # close it. The key is in the request object, which anyone who saw the request can
        # fetch, so encryption says nothing about who sent it. Beside a vp_token it is neither
        # an error nor a presentation, and it is refused, the request again left open: nothing
        # that carries an error is accepted. JSON null is no value, as a blank one is in a form.
        if body.get("error") is not None:
            if body.get("vp_token") is not None:
                return self._error("invalid_request", "the response carries both an error and "
                                                      "a vp_token")
            return self._wallet_error(session, body["error"], body.get("error_description"),
                                      encrypted=True)

        with self._lock:
            if session.answered:
                return self._error("invalid_request",
                                   "this request has already been answered; a second "
                                   "presentation for the same nonce is a replay")
            session.answered = True
            self._sessions.pop(session.state, None)
            self._by_request.pop(session.state, None)

        presentation = self._single_presentation(body.get("vp_token"))
        if presentation is None:
            return self._error("invalid_request",
                               "the vp_token is not one presentation for the one credential "
                               "the DCQL query asked for")

        # Only for a request that carried transaction_data; None leaves every claim it would
        # read unread, as before.
        binding = None
        if session.transaction_data:
            binding = TransactionDataBinding(session.transaction_data, self.query_id,
                                             scope=PER_CREDENTIAL, response_mode=RESPONSE_MODE,
                                             jti_fresh=self._jti_memory)
        verdict = verify_presentation(presentation,
                                      expected_nonce=session.nonce,
                                      expected_audience=self.client_id,
                                      issuer_jwks=self.issuer_jwks,
                                      trust_anchors=self.issuer_trust_anchors,
                                      # The type the DCQL query above actually asked for.
                                      # It was built into `meta.vct_values` and then never
                                      # passed here, so this verifier asked for one kind of
                                      # credential and accepted any kind the same issuer
                                      # signed. Measured 2026-09-17: a loyalty card's
                                      # `given_name` came back as though it were a PID's.
                                      expected_vct=self.vct_values,
                                      status_resolver=self.status_resolver,
                                      transaction_data=binding)
        if not verdict.authentic:
            # The reason goes to the operator through the returned verdict, and the wallet
            # gets the same constant refusal every other cause gets.
            return self._error(verdict.code, verdict.reason)

        # The claims the DCQL query above asked for. Every one is required (it names no
        # `claim_sets`), and a presentation that discloses fewer does not answer the request;
        # until 2026-10-01 a wallet that withheld one got the same 200 as one that did not.
        # A path is followed key by key through what was disclosed, so `age_equal_or_over.18`
        # is answered by that one statement and not by the object around it.
        disclosed = verdict.claims if isinstance(verdict.claims, dict) else {}
        missing, unaccepted = [], []
        for path, values in self.claims:
            found, value = disclosed_at(disclosed, path)
            if not found:
                missing.append(path)
            elif values is not None and not value_matches(value, values):
                unaccepted.append(path)
        if missing:
            return self._error("claims", "the presentation does not disclose %s, which the "
                                         "request asked for" % ", ".join(_shown(p) for p in missing))
        # The query's `values`: a wallet SHOULD return the claim only when it matches, so one
        # that returns another value has not answered, and `age_equal_or_over.18: false` must
        # not pass where `true` was asked for.
        if unaccepted:
            return self._error("claims", "the presentation discloses %s with a value the request "
                                         "does not accept" % ", ".join(_shown(p) for p in unaccepted))
        # OpenID4VP 1.0 section 6.4: a wallet MUST NOT send selectively disclosable claims the
        # request did not select. ERICA, the German EUDI Wallet programme's verifier testing
        # tool, sends one as a negative case (OVER_DISCLOSURE); until 2026-10-04 it got 200 and
        # the operator received claims nobody asked for. What the issuer signed in clear text is
        # not a disclosure and is not judged here.
        requested = [path for path, _ in self.claims]
        extra = sorted((p for p in verdict.disclosed if not _selected(p, requested)), key=repr)
        if extra:
            return self._error("claims", "the presentation discloses %s, which the request did "
                                         "not select" % ", ".join(_shown(p) for p in extra[:5]))

        # A status the operator's resolver CHECKED, whose value is not VALID (0): the issuer
        # says this credential is revoked or suspended. That is a fact, not a policy question, so
        # the wallet is refused; until 2026-10-01 it got 200. The states that are not a fact
        # (unreachable, no_authority, list_refused, unsupported_status) stay in the verdict for
        # the relying party's own policy, as the README's revocation section says.
        rev = verdict.revocation if isinstance(verdict.revocation, dict) else {}
        if rev.get("state") == "checked" and rev.get("status") != 0:
            # The refusal keeps the resolver's answer, so the operator sees why.
            return 400, dict(self.REFUSAL_BODY), Verdict(
                False, "revoked", "the issuer's status list gives this credential the value %r, "
                                  "not VALID (0)" % (rev.get("status"),), revocation=rev)

        # OpenID4VP 1.0 section 8.2: the redirect carries a fresh value only its receiver holds,
        # and this request's result is fetched with it, once (`redeem`). Until 2026-10-14 every
        # accepted response was sent to the same fixed URI, so in a same-device flow nothing
        # told the browser the wallet came back to from any other browser waiting on a result;
        # a request relayed to another person's wallet could complete the relayer's session
        # (section 14.2). `verdict.response_code` hands the code to the operator as well.
        if not self.redirect:
            return 200, {}, verdict
        code = secrets.token_urlsafe(RESPONSE_CODE_BYTES)
        verdict.response_code = code
        with self._lock:
            self._results[_sha256(code.encode("ascii"))] = (time.time(), session.state, verdict)
        # HAIP 5.1: 200, application/json, and ONLY a redirect_uri. The suite checks that
        # last part, so anything helpful added here fails the test.
        return 200, {"redirect_uri": _with_response_code(self.redirect_uri, code)}, verdict

    def redeem(self, response_code, state=None):
        """The verdict an accepted response left, given the `response_code` its redirect carried
        (OpenID4VP 1.0 section 8.2; section 13.3 has the reference design). Once: the second
        time, the same code gets None. None, too, for a code this verifier never issued, one
        older than the request lifetime, and, when `state` is given, one issued to another
        request: pass the state your own session holds. `serve`, which holds no session, passes
        none. A refusal, a wallet's error response and `redirect=False` issue no code.

        In a same-device flow, show a result only to the browser that presents its code. A
        cross-device flow cannot use it: the wallet's redirect lands on the wallet's device, not
        on the screen that showed the request, and section 14.2 calls that flow susceptible to
        a relayed request; its result reaches the operator through the returned verdict.
        """
        if not isinstance(response_code, str) or not response_code:
            return None
        if state is not None and not isinstance(state, str):
            return None
        key = _sha256(response_code.encode("utf-8"))
        with self._lock:
            self._expire_locked()
            entry = self._results.get(key)
            if entry is None:
                return None
            _, issued_to, verdict = entry
            if state is not None and issued_to != state:
                return None
            del self._results[key]
        return verdict

    #: The `id` of the one credential query in the request's DCQL, unless the verifier is given
    #: another (`credential_query_id`). OpenID4VP 1.0 section 8.1 keys `vp_token` by that id.
    #: Until 2026-09-27 the key was never compared: one presentation under any name was taken as
    #: the answer (found by mutating a genuine Credo response, lab/interop/credo/adversarial/).
    DCQL_QUERY_ID = "pid"

    def _single_presentation(self, vp_token):
        if not isinstance(vp_token, dict) or list(vp_token) != [self.query_id]:
            return None
        value = vp_token[self.query_id]
        if isinstance(value, list):
            if len(value) != 1:
                return None
            value = value[0]
        return value if isinstance(value, str) and value else None

    def _error_in_the_clear(self, form):
        """An Authorization Error Response posted without encryption, as OpenID4VP 1.0 section
        8.3.1 allows a wallet that cannot encrypt: `error`, `state` and an optional
        `error_description` as form parameters.

        It is processed only when its `state` names an outstanding request (section 14.3.2:
        "checking that the value of the received state parameter corresponds to a recent
        Authorization Request"), and processing it changes nothing: the request stays open for
        the wallet's own response. The `state` is in the request_uri a wallet is launched with,
        the QR code a person scans, so anyone who saw the request could send this. If it closed
        the request, an onlooker could cancel a presentation they could not make, or get in
        before the wallet does, and the record would say the holder declined. An error response
        encrypted to the request's key is answered the same way, for the same reason: the key
        is in the request object, which anyone who saw the request can fetch.
        """
        values = {name: _form_values(form, name)
                  for name in ("error", "error_description", "state")}
        if _form_values(form, "response") or _form_values(form, "vp_token"):
            return self._error("invalid_request", "the response carries both an error and a "
                                                  "presentation")
        # RFC 6749 section 3.1: "Request and response parameters MUST NOT be included more
        # than once."
        repeated = sorted(name for name, given in values.items() if len(given) > 1)
        if repeated:
            return self._error("invalid_request", "the error response repeats %s"
                                                  % ", ".join(repeated))
        state = values["state"][0] if values["state"] else None
        session = None
        if isinstance(state, str) and state:
            with self._lock:
                self._expire_locked()
                session = self._sessions.get(state)
        if session is None:
            return self._error("invalid_request", "the error response names no outstanding "
                                                  "request")
        description = values["error_description"][0] if values["error_description"] else None
        return self._wallet_error(session, values["error"][0], description, encrypted=False)

    def _wallet_error(self, session, error, description, *, encrypted):
        """Answer an Authorization Error Response for `session`: 200, `{}`, and a verdict that is
        never authentic. Refused instead when its `error` is not a code of the shape `_ERROR_CODE`
        holds, or its `error_description` is not a string. What the operator is shown of the
        description is `_printable`: it is the sender's free text."""
        if not isinstance(error, str) or not _ERROR_CODE.fullmatch(error):
            return self._error("invalid_request", "the error response's error is not an error "
                                                  "code: 1 to 64 letters, digits or underscores")
        if description is not None and not isinstance(description, str):
            return self._error("invalid_request", "the error response's error_description is "
                                                  "not a string")
        shown = _printable(description) if description else None
        reason = ("%s for request %s, which anyone who saw the request could send, so it does not "
                  "close the request" % (error, session.state))
        if shown is not None:
            reason += '; error_description "%s"' % shown
        return 200, {}, Verdict(False, "wallet_error", reason, wallet_error={
            "error": error, "error_description": shown, "state": session.state,
            "encrypted": encrypted})

    #: What every refused presentation gets back, whatever was wrong with it. One constant
    #: string, one status. Anything that varies with the CAUSE is an oracle: an attacker
    #: probes one check at a time and is told which one to work on next.
    REFUSAL_BODY = {"error": "invalid_request",
                    "error_description": "the presentation was not accepted"}

    @staticmethod
    def _error(code, description):
        """Refuse. The reason travels in the VERDICT, for the operator's log, never on the wire.

        This used to return the code and the reason in `error_description`, justified as
        debuggability for the wallet. That serves a cooperative wallet and hands an attacker
        a per-check oracle: seven distinct codes naming exactly which check failed, in the
        order they run. Worse, three of them leaked specifics. The audience refusal echoed
        this verifier's own client_id back. The freshness refusal stated the acceptance
        window in seconds, so an attacker learned it was 300 without probing for it. The
        decrypt refusal enumerated its causes, disclosing that outstanding-request state and
        an expiry exist at all.

        Timing remains an oracle and is NOT closed by this: a refusal that returns before the
        signature check is faster than one after it. That is measured by nobody here and is
        recorded as open rather than implied to be shut.
        """
        return 400, dict(Verifier.REFUSAL_BODY), Verdict(False, code, description)

    def _expire_locked(self):
        cutoff = time.time() - self.request_ttl_seconds
        for state in [s for s, sess in self._sessions.items() if sess.created < cutoff]:
            self._sessions.pop(state, None)
            self._by_request.pop(state, None)
        for key in [k for k, (when, _, _) in self._results.items() if when < cutoff]:
            self._results.pop(key, None)


def verify_response(request, vp_token, *, transaction_data_scope=None, issuer_jwks=None,
                    trust_anchors=None, now=None):
    """A verdict over a captured response: every presentation in `vp_token`, each held to the
    request it answers, and the request's transaction_data under both readings of which entries
    a key binding JWT binds.

    `request` is the authorization request's claims (the request object's payload as it was
    sent): its `nonce` and `client_id` (the key binding JWT's audience), `response_mode`,
    `dcql_query` (credential queries of format dc+sd-jwt; `meta.vct_values` is the type each asks
    for) and `transaction_data`. `vp_token` maps each credential query id to its one
    presentation (OpenID4VP 1.0 section 8.1). `now` evaluates the key binding JWTs at the instant
    they were captured, which a replayed capture needs.

    Each presentation is checked as `verify_presentation` checks it; the claims it discloses are
    returned, not judged against the query. With transaction_data every presentation is
    evaluated under PER_CREDENTIAL and under ALL_ENTRIES, each reading with its own jti memory,
    and `transaction_data_scope` names the reading that decides. Unnamed, the two decide only
    when they expect the same entries of every credential; otherwise `accepted` is None and
    `problem` asks for one. Nothing is accepted under a reading nobody chose.

    Under PER_CREDENTIAL an entry naming two or more presented credentials is bound by exactly
    one of their key binding JWTs, whichever the wallet chose: OpenID4VP 1.0 section 5.1, "If
    there is more than one element in the array, the Wallet MUST use only one of the referenced
    Credentials for transaction authorization." A response binding it twice, or nowhere, is
    refused although each presentation alone may be authentic.

    Returns {"accepted": True, False or None; "scope": the reading that decided, or None;
    "problem": why it was not accepted, or None; "expected": {reading: {query id: positions of
    the entries its key binding JWT must bind}}; "either": {position: query ids}, the entries
    exactly one of those credentials binds under PER_CREDENTIAL; "verdicts": {query id: Verdict}
    as decided; "readings": {reading: {query id: Verdict}}; "response_refusals": {reading: why
    the response is refused although its presentations are authentic, or None}}. Without
    transaction_data, "expected", "either", "readings" and "response_refusals" are empty and
    "verdicts" holds the one evaluation. Raises ValueError for a request nothing can be held to.
    """
    if transaction_data_scope is not None and transaction_data_scope not in TRANSACTION_DATA_SCOPES:
        raise ValueError("the transaction_data scope is %r; it is one of %s"
                         % (transaction_data_scope, ", ".join(TRANSACTION_DATA_SCOPES)))
    if not isinstance(request, dict):
        raise ValueError("the request is a JSON object of the authorization request's claims")
    nonce, audience = request.get("nonce"), request.get("client_id")
    if not (isinstance(nonce, str) and nonce and isinstance(audience, str) and audience):
        raise ValueError("the request names no nonce or no client_id, and a key binding JWT is "
                         "checked against both")
    dcql = request.get("dcql_query")
    queries = dcql.get("credentials") if isinstance(dcql, dict) else None
    if not isinstance(queries, list) or not queries:
        raise ValueError("the request's dcql_query has no credentials")
    asked = {}
    for query in queries:
        qid = query.get("id") if isinstance(query, dict) else None
        if not isinstance(qid, str) or not _DCQL_ID.fullmatch(qid) or qid in asked:
            raise ValueError("a credential query's id is missing, malformed or repeated: %r" % (qid,))
        if query.get("format") != "dc+sd-jwt":
            raise ValueError("credential query %r asks for format %r; this verifier checks "
                             "dc+sd-jwt only" % (qid, query.get("format")))
        meta = query.get("meta") if isinstance(query.get("meta"), dict) else {}
        vct = meta.get("vct_values")
        asked[qid] = vct if isinstance(vct, list) else None
    entries = []
    if request.get("transaction_data") is not None:
        raw = request["transaction_data"]
        if not isinstance(raw, list) or not raw:
            raise ValueError("the request's transaction_data is not a non-empty array")
        for position, item in enumerate(raw):
            try:
                entry = TransactionDataEntry(item)
            except ValueError as exc:
                raise ValueError("transaction_data entry %d: %s" % (position, exc)) from None
            unknown = [i for i in entry.credential_ids if i not in asked]
            if unknown:
                raise ValueError("transaction_data entry %d names %s, which the request's "
                                 "dcql_query does not ask for" % (position, ", ".join(unknown)))
            entries.append(entry)
        if any(e.is_ts12 for e in entries) and not isinstance(request.get("response_mode"), str):
            raise ValueError("the request carries TS12 transaction data and names no "
                             "response_mode, which TS12 3.6 has the key binding JWT repeat")

    out = {"accepted": False, "scope": None, "problem": None, "expected": {}, "either": {},
           "verdicts": {}, "readings": {}, "response_refusals": {}}
    if entries:
        # Every query is presented, or the vp_token is refused below, so `asked` is `presented`.
        out["expected"] = {scope: {qid: list(TransactionDataBinding(
            entries, qid, scope=scope, response_mode=None, jti_fresh=None, presented=asked).expected)
            for qid in asked} for scope in TRANSACTION_DATA_SCOPES}
        out["either"] = {position: [q for q in asked if q in entry.credential_ids]
                         for position, entry in enumerate(entries)
                         if sum(q in entry.credential_ids for q in asked) > 1}
    if not isinstance(vp_token, dict) or set(vp_token) != set(asked):
        out["problem"] = ("the vp_token does not answer the request: it holds %s and the "
                          "dcql_query asks for %s"
                          % (sorted(vp_token) if isinstance(vp_token, dict) else "no object",
                             sorted(asked)))
        return out
    presented = {}
    for qid in asked:
        value = vp_token[qid]
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if not isinstance(value, str) or not value:
            out["problem"] = "the vp_token holds no single presentation for %r" % qid
            return out
        presented[qid] = value

    def evaluate(scope):
        memory = JtiMemory()
        return {qid: verify_presentation(
            presentation, expected_nonce=nonce, expected_audience=audience,
            issuer_jwks=issuer_jwks, trust_anchors=trust_anchors, now=now,
            expected_vct=asked[qid],
            transaction_data=None if not entries else TransactionDataBinding(
                entries, qid, scope=scope, response_mode=request.get("response_mode"),
                jti_fresh=memory, presented=presented))
            for qid, presentation in presented.items()}

    def bound_once(verdicts):
        """Section 5.1 across the response: each entry naming several presented credentials is
        bound by exactly one of their key binding JWTs. None when so, else why not."""
        for position, qids in sorted(out["either"].items()):
            if not all(verdicts[q].authentic for q in qids):
                continue            # a refused presentation refuses the response already
            by = [q for q in qids if position in verdicts[q].transaction_data["bound"]]
            if not by:
                return ("transaction_data_missing: entry %d names the presented credentials %s "
                        "and no key binding JWT binds it; OpenID4VP 1.0 section 5.1 has the "
                        "wallet authorize it with one of them" % (position, ", ".join(qids)))
            if len(by) > 1:
                return ("transaction_data_extra: entry %d is bound by %s; OpenID4VP 1.0 section "
                        "5.1: \"the Wallet MUST use only one of the referenced Credentials for "
                        "transaction authorization\"" % (position, " and ".join(by)))
        return None

    if not entries:
        out["verdicts"] = evaluate(None)
    else:
        out["readings"] = {scope: evaluate(scope) for scope in TRANSACTION_DATA_SCOPES}
        out["response_refusals"] = {PER_CREDENTIAL: bound_once(out["readings"][PER_CREDENTIAL]),
                                    ALL_ENTRIES: None}
        if transaction_data_scope is None and (out["expected"][PER_CREDENTIAL]
                                               != out["expected"][ALL_ENTRIES]):
            out["accepted"] = None
            out["problem"] = ("the two readings expect different entries of these credentials "
                              "(see expected); name the transaction_data scope, %s, to decide"
                              % " or ".join(TRANSACTION_DATA_SCOPES))
            return out
        out["scope"] = transaction_data_scope
        out["verdicts"] = out["readings"][transaction_data_scope or PER_CREDENTIAL]
    refused = [(qid, v) for qid, v in out["verdicts"].items() if not v.authentic]
    response_refusal = out["response_refusals"].get(out["scope"] or PER_CREDENTIAL)
    out["accepted"] = not refused and response_refusal is None
    if refused:
        qid, verdict = refused[0]
        out["problem"] = "%s: %s: %s" % (qid, verdict.code, verdict.reason)
    elif response_refusal is not None:
        out["problem"] = response_refusal
    return out


def _sha256(raw):
    import hashlib
    return hashlib.sha256(raw).digest()


def _with_response_code(uri, code):
    """`uri` with `response_code=<code>` added to its query, before any fragment, and nothing
    else of it changed. The code is URL-safe base64, so it needs no escaping."""
    base, hash_mark, fragment = uri.partition("#")
    return "%s%sresponse_code=%s%s%s" % (base, "&" if "?" in base else "?", code, hash_mark,
                                         fragment)


def _sign_es256(key, header, claims):
    header_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = b64u_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = (header_b64 + "." + claims_b64).encode("ascii")
    r, s = asym_utils.decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return header_b64 + "." + claims_b64 + "." + b64u_encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big"))
