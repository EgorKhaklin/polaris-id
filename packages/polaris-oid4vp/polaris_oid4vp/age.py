# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""age.py -- the verifier behind the age page, `serve --age-check 18|21` (experimental).

THE REQUEST. One request over the Digital Credentials API, protocol `openid4vp-v1-signed`, as
`Verifier.dc_api_request` makes one. Its DCQL query asks for one element, `age_over_18` or
`age_over_21`, once for each docType the configured roots are bound to, in that docType's
namespace (AGE_DOCTYPES), with `intent_to_retain` false and no `values`. More than one docType,
and the queries are the options of one credential set (OpenID4VP 1.0 section 6.2), so a wallet
answers with one document of one docType.

THE ROOTS. Each root is bound to one docType (`AgeRoot`), so a document is held only to the roots
of its own docType. `load_age_roots` reads them from a JSON array of `{"label", "doctype", "pem",
"sha256"}`: `pem` a file path, relative to the array's own file, and `sha256` the SHA-256 of
that file's bytes, in hex. A root whose file does not hash to its pin, a docType outside
AGE_DOCTYPES, an empty array and an entry with any other member are refused.

THE ANSWER. `AgeVerifier.age_answer` judges what the page posts and returns one of three strings:
"N or over" when the one element is the boolean true, "under N" when it is false, and
COULD_NOT_CHECK for everything else, a refusal, a wallet's error and an element that is not a
boolean among them. The element is read by its type: 1, "true" and a byte string are not true.
The request ends at its answer, whatever the answer is.
"""

import hashlib
import pathlib
import re

from . import mdoc
from .jwe import _loads_depth_bounded, b64u_decode
from .mdoc import IacaRoot
from .sdjwt import Verdict
from .verifier import (DEFAULT_REQUEST_TTL_SECONDS, MDOC_FORMAT, Verifier, _encryption_jwk,
                       mdoc_query_refusal)

#: The ages the page asks about.
AGES = (18, 21)

#: The docTypes the page asks for, each with the namespace its age element is in: the mDL and an
#: ID pass in ISO/IEC 18013-5's namespace, the EU age attestation in its own (the AV profile,
#: Annex A, A.4).
AGE_DOCTYPES = {
    "org.iso.18013.5.1.mDL": "org.iso.18013.5.1",
    "com.google.wallet.idcard.1": "org.iso.18013.5.1",
    "eu.europa.ec.av.1": "eu.europa.ec.av.1",
}

#: The id of each docType's credential query.
QUERY_IDS = {
    "org.iso.18013.5.1.mDL": "mdl",
    "com.google.wallet.idcard.1": "idcard",
    "eu.europa.ec.av.1": "av",
}

#: The answer for everything that is not a boolean element, judged authentic.
COULD_NOT_CHECK = "could not check"

_ENTRY_MEMBERS = frozenset(("label", "doctype", "pem", "sha256"))
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def answer_over(age):
    return "%d or over" % age


def answer_under(age):
    return "under %d" % age


def _age(age):
    if type(age) is not int or age not in AGES:
        raise ValueError("the age is 18 or 21, not %r" % (age,))
    return age


class AgeRoot:
    """One root the page trusts: its label, the one docType it is bound to, and its PEM."""

    __slots__ = ("label", "doctype", "pem", "sha256", "iaca_root")

    def __init__(self, label, doctype, pem):
        if not isinstance(label, str) or not label.strip():
            raise ValueError("the label is a non-empty string")
        if doctype not in AGE_DOCTYPES:
            raise ValueError("docType %r is not one the page asks for: %s"
                             % (doctype, ", ".join(AGE_DOCTYPES)))
        if not isinstance(pem, bytes):
            raise ValueError("the PEM is bytes")
        self.label, self.doctype, self.pem = label, doctype, pem
        self.sha256 = hashlib.sha256(pem).hexdigest()
        self.iaca_root = IacaRoot(pem, [doctype])


def load_age_roots(path):
    """The AgeRoots of the JSON array in the file at `path`. ValueError says which entry, and
    what to change."""
    path = pathlib.Path(path)
    try:
        entries = _loads_depth_bounded(path.read_text(encoding="utf-8"), "file", finite=True)
    except (OSError, ValueError) as exc:
        raise ValueError("the file is not read: %s" % exc) from None
    if not isinstance(entries, list):
        raise ValueError("the file is a JSON array of roots, each {label, doctype, pem, sha256}")
    if not entries:
        raise ValueError("the file holds no root, so no document could be read")
    roots = []
    for number, entry in enumerate(entries, 1):
        label = entry.get("label") if isinstance(entry, dict) else None
        named = "entry %d (%s)" % (number, label) if isinstance(label, str) and label else "entry %d" % number
        if not isinstance(entry, dict):
            raise ValueError("%s: an entry is an object of label, doctype, pem and sha256" % named)
        if frozenset(entry) != _ENTRY_MEMBERS:
            raise ValueError("%s: an entry has exactly label, doctype, pem and sha256; this one has %s"
                             % (named, ", ".join(sorted(entry)) or "none"))
        pin, name = entry["sha256"], entry["pem"]
        if not isinstance(pin, str) or not _SHA256_HEX.fullmatch(pin):
            raise ValueError("%s: sha256 is 64 lowercase hex digits" % named)
        if not isinstance(name, str) or not name:
            raise ValueError("%s: pem is the path of a PEM file" % named)
        try:
            pem = (path.parent / name).read_bytes()
        except OSError as exc:
            raise ValueError("%s: %s: %s" % (named, name, exc.strerror or exc)) from None
        digest = hashlib.sha256(pem).hexdigest()
        if digest != pin:
            raise ValueError("%s: %s has SHA-256 %s, not its pin %s" % (named, name, digest, pin))
        try:
            roots.append(AgeRoot(label, entry["doctype"], pem))
        except ValueError as exc:
            raise ValueError("%s: %s" % (named, exc)) from None
    return roots


class AgeVerifier(Verifier):
    """A verifier for the age page: `Verifier` built for `mso_mdoc`, whose request over the Digital
    Credentials API asks for one age element (the module's docstring), and whose answer is one of
    three strings (`age_answer`). Its other request paths are not used by the page, and
    `new_request` refuses."""

    def __init__(self, *, age, roots, client_cert_pem, client_key_pem, request_uri, response_uri,
                 request_ttl_seconds=DEFAULT_REQUEST_TTL_SECONDS, dc_api_client_metadata=None):
        self.age = _age(age)
        roots = list(roots) if isinstance(roots, (list, tuple)) else None
        if not roots or not all(isinstance(root, AgeRoot) for root in roots):
            raise ValueError("roots is a non-empty list of AgeRoot")
        self.age_roots = roots
        self.age_element = "age_over_%d" % self.age
        doctypes = []
        for root in roots:
            if root.doctype not in doctypes:
                doctypes.append(root.doctype)
        #: {query id: docType}, in the order the roots name them.
        self.age_queries = {QUERY_IDS[doctype]: doctype for doctype in doctypes}
        super().__init__(client_cert_pem=client_cert_pem, client_key_pem=client_key_pem,
                         request_uri=request_uri, response_uri=response_uri,
                         request_ttl_seconds=request_ttl_seconds, credential_format=MDOC_FORMAT,
                         doctype_value=doctypes[0], claims=[[AGE_DOCTYPES[doctypes[0]], self.age_element]],
                         iaca_roots=[root.iaca_root for root in roots],
                         credential_query_id=QUERY_IDS[doctypes[0]], redirect=False,
                         dc_api_client_metadata=dc_api_client_metadata)

    def new_request(self, *args, **kwargs):
        raise ValueError("the age page makes its requests over the Digital Credentials API only")

    def _dcql_query(self, claims=None, vct_values=None):
        credentials = [{"id": qid, "format": MDOC_FORMAT, "meta": {"doctype_value": doctype},
                        "claims": [{"path": [AGE_DOCTYPES[doctype], self.age_element], "intent_to_retain": False}]}
                       for qid, doctype in self.age_queries.items()]
        query = {"credentials": credentials}
        if len(credentials) > 1:
            query["credential_sets"] = [{"options": [[c["id"]] for c in credentials]}]
        return query

    def _single_presentation(self, vp_token):
        """(query id, the one DeviceResponse) when `vp_token` answers exactly one of the queries,
        with one value; else None."""
        if not isinstance(vp_token, dict) or len(vp_token) != 1:
            return None
        (qid, value), = vp_token.items()
        if qid not in self.age_queries:
            return None
        if isinstance(value, list):
            if len(value) != 1:
                return None
            value = value[0]
        return (qid, value) if isinstance(value, str) and value else None

    def _judge_dc_api(self, session, presentation):
        verdict = self._judge_age(session, presentation)
        if not verdict.authentic:
            # The request ends at its answer: a refused one is not left open for another try.
            with self._lock:
                session.answered = True
                if self._dc_api.get(session.nonce) is session:
                    del self._dc_api[session.nonce]
        return verdict

    def _judge_age(self, session, answered):
        if answered is None:
            return Verdict(False, "malformed", "the vp_token is not one DeviceResponse for one of the "
                                               "credential queries the request made")
        qid, presentation = answered
        doctype = self.age_queries[qid]
        path = (AGE_DOCTYPES[doctype], self.age_element)
        try:
            device_response = b64u_decode(presentation)
        except ValueError:
            return Verdict(False, "malformed", "the vp_token value is not a base64url DeviceResponse "
                                               "(OpenID4VP 1.0 B.2.5)")
        transcript = mdoc.dc_api_session_transcript(
            origin=session.origin, nonce=session.nonce,
            jwk_thumbprint=mdoc.jwk_thumbprint(_encryption_jwk(session.enc_key, session.kid)))
        verdict, elements = mdoc.judge_device_response(device_response, session_transcript=transcript,
                                                       iaca_roots=self.iaca_roots, doctype=doctype)
        if not verdict.authentic:
            return verdict
        refusal = mdoc_query_refusal([(path, None)], elements)
        if refusal is not None:
            return Verdict(False, *refusal)
        if type(elements[path]) is not bool:
            return Verdict(False, "claims", "the presentation discloses %s/%s with a value that is not a "
                                            "boolean" % path)
        return verdict

    def age_answer(self, data, *, origin):
        """The answer to what the page posts: `answer_over(age)`, `answer_under(age)` or
        COULD_NOT_CHECK, beside the verdict it came from (None when no verdict was reached).
        `data` and `origin` are `dc_api_response`'s. Nothing it is given makes it raise."""
        status, _, verdict = self.dc_api_response(data, origin=origin)
        if status != 200 or verdict is None or not verdict.authentic:
            return COULD_NOT_CHECK, verdict
        (table,) = verdict.claims.values()
        (value,) = table.values()
        return (answer_over(self.age) if value else answer_under(self.age)), verdict
