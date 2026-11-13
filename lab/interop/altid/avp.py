# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The age-verification profile (AVP) layer over the lab's mdoc verifier: one request for age_over_18 of an
eu.europa.ec.av.1 document, its record, and the response checks of the integration guide's Appendix D (Table 11).
Steps 6 to 10 and 12 are ../mdoc/verify_mdoc.py's own; the rest are here.

    new_transaction(base_url, flow, browser)   the request parameters, its two link forms and its record
    check_request(params)                      the request rules this layer holds itself to before one leaves
    read_pins(path), anchors_from(pems, pins)  the trust list: every certificate in it must be pinned by SHA-256
    verify_avp(form, record, anchors, at)      steps 1 to 12 and 14 on one form POST; a Refused names the step
    Transactions                               the records under one lock: step 13, the answers, the capture

Lab code. The product does not use it, and it asks for nothing but this one claim.
"""
import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
import re
import secrets
import threading
import urllib.parse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vm = _load("verify_mdoc_for_avp", os.path.join(HERE, "..", "mdoc", "verify_mdoc.py"))
Refused = vm.Refused

DOCTYPE = NAMESPACE = "eu.europa.ec.av.1"
CLAIM = "age_over_18"
QUERY_ID = "proof_of_age"
DCQL = {"credentials": [{"id": QUERY_ID, "format": "mso_mdoc", "meta": {"doctype_value": DOCTYPE},
                         "claims": [{"path": [NAMESPACE, CLAIM]}]}]}
LIFETIME = datetime.timedelta(minutes=10)  # 4.3.1.1: flows without redirect SHOULD limit the request's lifetime
APP_LINK = "https://app.test.tegnebog.dk/oid4vp"  # 9.1's application link, test environment
AV_LINK = "av://"  # Table 3's scheme for the AVP request
BROWSERS = ("app", "safari", "brave", "duck", "chrome", "edge", "firefox", "opera", "samsung")  # Table 6
OPEN, COMPLETED, FAILED = "open", "completed", "failed"
MAX_OPEN = 64
_B64U = re.compile(r"[A-Za-z0-9_-]+")
_SHA256 = re.compile(r"[0-9a-f]{64}")
# The shape of an OAuth error code, as packages/polaris-oid4vp/polaris_oid4vp/verifier.py holds it (_ERROR_CODE).
_ERROR_CODE = re.compile(r"[A-Za-z0-9_]{1,64}")
_TXID = re.compile(r"[A-Za-z0-9_-]{43}")


def _quiet(check, detail):
    return None


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def stamp(when):
    return when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stamp(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text, check):
    """Base64url, unpadded or with its padding, and nothing else."""
    body = text.rstrip("=") if isinstance(text, str) else None
    if not body or not _B64U.fullmatch(body) or len(text) - len(body) > 2 or len(body) % 4 == 1:
        raise Refused(check, "not base64url")
    return base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


# --- the request -----------------------------------------------------------------------------------

def detect_browser(user_agent):
    """Table 6's "browser" value for a User-Agent, or "app" when none is named. Brave sends Chrome's User-Agent, so
    it reads as chrome here. Only the value is kept, never the header."""
    ua = user_agent or ""
    for value, marks in (("samsung", ("SamsungBrowser/",)), ("edge", ("Edg/", "EdgA/", "EdgiOS/")),
                         ("opera", ("OPR/", "OPT/", "Opera/")), ("duck", ("DuckDuckGo/",)),
                         ("firefox", ("Firefox/", "FxiOS/")), ("chrome", ("Chrome/", "CriOS/")),
                         ("safari", ("Safari/",))):
        if any(m in ua for m in marks):
            return value
    return "app"


def check_request(params):
    """The request rules this layer holds before a request leaves: exactly the AVP parameters, client_id exactly
    "redirect_uri:" + response_uri (Table 3), direct_post in the clear, the one DCQL query, a 128-bit nonce."""
    want = {"response_type", "response_mode", "client_id", "response_uri", "dcql_query", "nonce", "state"}
    if set(params) != want:
        raise Refused("request", "parameters %s differ from the profile's" % sorted(set(params) ^ want))
    if params["client_id"] != "redirect_uri:" + params["response_uri"]:
        raise Refused("request", "client_id is not \"redirect_uri:\" + response_uri")
    if (params["response_type"], params["response_mode"]) != ("vp_token", "direct_post"):
        raise Refused("request", "response_type and response_mode are not vp_token and direct_post")
    if json.loads(params["dcql_query"]) != DCQL:
        raise Refused("request", "the DCQL query is not the one age_over_18 query")
    if len(b64u_decode(params["nonce"], "request")) < 16:
        raise Refused("request", "the nonce is under 128 bits")


def new_transaction(base_url, flow="qr", browser=None, now=None):
    """A new request: (params, links, record). base_url is the public https origin the phone reaches."""
    u = urllib.parse.urlsplit(base_url)
    if u.scheme != "https" or not u.hostname or u.query or u.fragment or u.username or u.password:
        raise ValueError("the base URL must be https, with a host and no query, fragment or user: %r" % base_url)
    if flow not in ("qr", "link"):
        raise ValueError("flow is qr or link, not %r" % (flow,))
    now = now or utcnow()
    txid = b64u(secrets.token_bytes(32))
    response_uri = base_url.rstrip("/") + "/response/" + txid
    params = {"response_type": "vp_token", "response_mode": "direct_post", "client_id": "redirect_uri:" + response_uri,
              "response_uri": response_uri, "dcql_query": json.dumps(DCQL, separators=(",", ":")),
              "nonce": b64u(secrets.token_bytes(16)), "state": txid}
    check_request(params)
    query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    links = {"app": APP_LINK + "?" + query, "av": AV_LINK + "?" + query}
    record = {"txid": txid, "state": txid, "nonce": params["nonce"], "response_uri": response_uri,
              "client_id": params["client_id"], "flow": flow,
              "browser": (browser if browser in BROWSERS else "app") if flow == "link" else None,
              "created": stamp(now), "expires": stamp(now + LIFETIME), "status": OPEN}
    return params, links, record


# --- the trust list ----------------------------------------------------------------------------------

def read_pins(path):
    """trust/PINS: one SHA-256 (hex) per line, then anything; # starts a comment. Empty is refused."""
    pins = set()
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            token = line.split()[0].lower()
            if not _SHA256.fullmatch(token):
                raise Refused("trust list", "a PINS line is not a SHA-256: %r" % line[:80])
            pins.add(token)
    if not pins:
        raise Refused("trust list", "PINS holds no SHA-256")
    return pins


def anchors_from(pem_paths, pins):
    """Every certificate in the given PEM files, each refused unless its DER's SHA-256 is pinned."""
    pins = {p.lower() for p in pins}
    if not pem_paths:
        raise Refused("trust list", "no trust anchor")
    anchors = []
    for path in pem_paths:
        with open(path, "rb") as f:
            data = f.read()
        try:
            certs = x509.load_pem_x509_certificates(data)
        except ValueError as e:
            raise Refused("trust list", "%s is not PEM X.509 (%s)" % (os.path.basename(path), e))
        for cert in certs:
            digest = hashlib.sha256(_der(cert)).hexdigest()
            if digest not in pins:
                raise Refused("trust list", "%s holds a certificate whose SHA-256 %s is not pinned" % (
                    os.path.basename(path), digest))
            anchors.append(cert)
    return anchors


def _self_signed(cert):
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


# --- the response ------------------------------------------------------------------------------------

def _one(form, name, check):
    values = form.get(name)
    if not values:
        raise Refused(check, "no %s" % name)
    if len(values) != 1 or not isinstance(values[0], str):
        raise Refused(check, "%s appears %d times" % (name, len(values)))
    return values[0]


def verify_avp(form, record, anchors, at, log=_quiet, keep=None):
    """Appendix D on one form POST ({name: [values]}) against its record. Returns the verdict
    {"satisfied", "vp_token_form", "disclosed"}; raises Refused at the first step that fails. `keep`, a dict, gets
    the decoded DeviceResponse bytes and the vp_token form as soon as each is known."""
    keep = {} if keep is None else keep
    try:
        return _verify_avp(form, record, anchors, at, log, keep)
    except Refused:
        raise
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as e:
        raise Refused("malformed", "%s: %s" % (type(e).__name__, e))


def _verify_avp(form, record, anchors, at, log, keep):
    # 1. A vp_token, once. OpenID4VP 1.0 8.1 sends a JSON object keyed by the DCQL query id, holding one
    #    presentation; the guide's example (10.2) sends the presentation string itself. Both are taken, and which
    #    one arrived is recorded.
    token = _one(form, "vp_token", "vp_token")
    if token.lstrip().startswith("{"):
        try:
            obj = json.loads(token)
        except ValueError:
            raise Refused("vp_token", "neither a presentation nor a JSON object")
        if not (isinstance(obj, dict) and set(obj) == {QUERY_ID} and isinstance(obj[QUERY_ID], list)
                and len(obj[QUERY_ID]) == 1 and isinstance(obj[QUERY_ID][0], str)):
            raise Refused("vp_token", "the object is not {%r: [one presentation]}" % QUERY_ID)
        shape, token = "object", obj[QUERY_ID][0]
    else:
        shape = "string"
    keep["vp_token_form"] = shape
    # 2. Base64url, then CBOR.
    raw = b64u_decode(token, "vp_token")
    keep["device_response"] = raw
    resp = vm.load_all(raw)
    # 3. A map with version, documents and status.
    if not isinstance(resp, dict) or not {"version", "documents", "status"} <= set(resp) or resp["version"] != "1.0":
        raise Refused("device response", "not a DeviceResponse map with version 1.0, documents and status")
    # 4. Status 0 and exactly one Document, of the requested docType.
    if resp["status"] != 0:
        raise Refused("device response", "status %r, not 0" % (resp["status"],))
    docs = resp["documents"]
    if not isinstance(docs, list) or len(docs) != 1:
        raise Refused("device response", "%s documents, not exactly one" % (
            len(docs) if isinstance(docs, list) else "no array of"))
    doc = docs[0]
    if not isinstance(doc, dict) or doc.get("docType") != DOCTYPE:
        raise Refused("requested docType", "the request asked for %r, the document is %r" % (
            DOCTYPE, doc.get("docType") if isinstance(doc, dict) else None))
    log("device response", "version 1.0, status 0, one %s document; vp_token as a %s" % (DOCTYPE, shape))
    # 5. The x5chain, and its last certificate: self-signed and in the trust list. That the chain is ordered, from
    #    the issuer certificate to it, verify_mdoc's chain_to_root holds (each certificate issued by the next).
    issuer_signed = doc.get("issuerSigned")
    if not isinstance(issuer_signed, dict):
        raise Refused("document", "no issuerSigned")
    _, prot, unprot, payload, _ = vm.cose_sign1(issuer_signed.get("issuerAuth"), "issuer signature")
    x5 = vm.x5chain_of(prot, unprot)
    try:
        chain = [x509.load_der_x509_certificate(c) for c in x5]
    except ValueError as e:
        raise Refused("issuer chain", "an x5chain certificate is not DER X.509 (%s)" % e)
    last = chain[-1]
    if not any(_der(a) == _der(last) for a in anchors):
        raise Refused("trust list", "the last x5chain certificate (%s, SHA-256 %s) is not in the trust list" % (
            last.subject.rfc4514_string(), hashlib.sha256(_der(last)).hexdigest()))
    if not _self_signed(last):
        raise Refused("trust list", "the last x5chain certificate %s is not self-signed" % last.subject.rfc4514_string())
    log("trust list", "the last of %d x5chain certificate(s) is self-signed and pinned: SHA-256 %s" % (
        len(chain), hashlib.sha256(_der(last)).hexdigest()))
    # 6 to 10 and 12: verify_mdoc.verify_document, with that certificate as its one root, over the AVP
    # SessionTranscript (5.6: OpenID4VPHandover from the record's client_id, nonce and response_uri, and a null
    # jwkThumbprint, since the response is not encrypted).
    transcript, _ = vm.session_transcript({"client_id": record["client_id"], "nonce": record["nonce"],
                                           "response_uri": record["response_uri"], "response_mode": "direct_post",
                                           "encryption_jwk": None})
    elements = vm.verify_document(doc, transcript, [last], at, log, enforce_profile=True)
    # 11. A Proof of Age carries no status element, so one present is refused. That is this lab's decision, failing
    #     closed. It is judged on the MSO verify_document authenticated, so a response that also fails step 12 is
    #     refused at 12.
    mso = vm.load_all(vm.load_all(payload).inner)
    if "status" in mso:
        raise Refused("status", "the MSO carries a status element, which a Proof of Age does not")
    # 13, the form's half: the state names this transaction. (The record's half, not yet completed and then marked
    #     so, is Transactions.respond's, under its lock.)
    state = _one(form, "state", "state")
    if not hmac.compare_digest(state.encode("utf-8"), record["state"].encode("utf-8")):
        raise Refused("state", "the state differs from the request's")
    # 14. age_over_18 true satisfies; false, or no such element, does not.
    value = elements.get((NAMESPACE, CLAIM))
    satisfied = value is True
    log("verdict", "%s/%s is %r: %s" % (NAMESPACE, CLAIM, value, "satisfied" if satisfied else "not satisfied"))
    return {"satisfied": satisfied, "vp_token_form": shape, "disclosed": sorted("%s/%s" % k for k in elements)}


# --- the records, the answers and the capture -------------------------------------------------------

def _refusal(check):
    return {"error": "invalid_request", "error_description": "The presentation was not accepted (%s)." % check}


NO_TRANSACTION = {"error": "invalid_request", "error_description": "There is no open request at this address."}


class Transactions:
    """The records, under one lock. A POST to an open transaction is judged and closes it before the answer leaves,
    whatever the verdict (Appendix D step 13, Table 7 step 15). Each record written to runs/<txid>/ holds what the
    lab keeps of a flow; nothing else is written."""

    def __init__(self, base_url, anchors, runs_dir=None, clock=None):
        self.base_url, self.anchors, self.runs_dir = base_url, list(anchors), runs_dir
        self.clock = clock or utcnow
        self._lock = threading.Lock()
        self._records = {}
        self._codes = {}

    def _open(self, record, now):
        return record["status"] == OPEN and now <= parse_stamp(record["expires"])

    def _write(self, txid, name, data):
        if not self.runs_dir:
            return
        d = os.path.join(self.runs_dir, txid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "wb" if isinstance(data, bytes) else "w") as f:
            f.write(data)

    def _save(self, record):
        self._write(record["txid"], "record.json", json.dumps(record, indent=1, sort_keys=True) + "\n")

    def new(self, flow="qr", browser=None):
        with self._lock:
            now = self.clock()
            if sum(1 for r in self._records.values() if self._open(r, now)) >= MAX_OPEN:
                raise Refused("request", "%d requests are open" % MAX_OPEN)
            params, links, record = new_transaction(self.base_url, flow, browser, now)
            self._records[record["txid"]] = record
            self._write(record["txid"], "request.txt", "%s\n%s\n" % (links["app"], links["av"]))
            self._save(record)
            return params, links, dict(record)

    def record(self, txid):
        with self._lock:
            r = self._records.get(txid)
            return dict(r) if r else None

    def done(self, code):
        """The verdict of the same-device transaction a response_code names, once."""
        with self._lock:
            txid = self._codes.pop(code, None) if isinstance(code, str) else None
            return dict(self._records[txid]) if txid else None

    def respond(self, txid, content_type, body):
        """One POST to a response_uri. Returns (http status, JSON object)."""
        with self._lock:
            now = self.clock()
            record = self._records.get(txid) if isinstance(txid, str) and _TXID.fullmatch(txid) else None
            if record is None or not self._open(record, now):
                return 400, NO_TRANSACTION
            record["closed"] = stamp(now)
            try:
                return self._judge(record, content_type, body, now)
            finally:
                self._save(record)

    def _judge(self, record, content_type, body, now):
        txid = record["txid"]
        self._write(txid, "post-body.sha256", hashlib.sha256(body).hexdigest() + "\n")
        try:
            if (content_type or "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
                raise Refused("request body", "the body is not application/x-www-form-urlencoded")
            try:
                form = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
            except (UnicodeDecodeError, ValueError):
                raise Refused("request body", "the body is not a form")
        except Refused as e:
            record.update(status=FAILED, refused=e.check)
            return 400, _refusal(e.check)
        if "error" in form:
            return self._error_response(record, form)
        lines, keep = [], {}

        def log(check, detail):
            lines.append("  ok   %-18s %s" % (check, detail))
        try:
            verdict = verify_avp(form, record, self.anchors, now, log, keep)
        except Refused as e:
            record.update(status=FAILED, refused=e.check, vp_token_form=keep.get("vp_token_form"))
            lines.append("REFUSED    %s" % e)
            self._capture(record, keep, lines, now)
            return 400, _refusal(e.check)
        record.update(status=COMPLETED, satisfied=verdict["satisfied"], vp_token_form=verdict["vp_token_form"])
        lines.append("VERIFIED   %s" % ("satisfied" if verdict["satisfied"] else "not satisfied"))
        self._capture(record, keep, lines, now)
        if record["flow"] != "link":
            return 200, {}
        code = b64u(secrets.token_bytes(16))
        self._codes[code] = txid
        return 200, {"redirect_uri": self.base_url.rstrip("/") + "/done?response_code=" + code,
                     "browser": record["browser"]}

    def _error_response(self, record, form):
        """An Authorization Error Response (OpenID4VP 1.0 8.5; the guide's 8.1): error and state, and an optional
        error_description, which is not kept (8.1: it may leak information about the user). Processed, it gets 200
        with a JSON object (OpenID4VP 1.0 8.2: "MUST respond with an HTTP status code of 200 with Content-Type of
        application/json and a JSON object in the response body"), and the record is failed with the code alone."""
        try:
            if "vp_token" in form:
                raise Refused("error response", "an error beside a vp_token")
            code = _one(form, "error", "error response")
            if not _ERROR_CODE.fullmatch(code):
                raise Refused("error response", "the error is not an error code")
            if len(form.get("error_description", [])) > 1:
                raise Refused("error response", "error_description appears more than once")
            state = _one(form, "state", "state")
            if not hmac.compare_digest(state.encode("utf-8"), record["state"].encode("utf-8")):
                raise Refused("state", "the state differs from the request's")
        except Refused as e:
            record.update(status=FAILED, refused=e.check)
            return 400, _refusal(e.check)
        record.update(status=FAILED, error=code)
        return 200, {}

    def _capture(self, record, keep, lines, now):
        """runs/<txid>/ in the input format verify_mdoc.py reads, so both verifiers can run on it again offline."""
        txid = record["txid"]
        if "device_response" in keep:
            self._write(txid, "device-response.cbor", keep["device_response"])
        inputs = {"client_id": record["client_id"], "response_uri": record["response_uri"], "nonce": record["nonce"],
                  "response_mode": "direct_post", "jwk_thumbprint": None, "encryption_jwk": None,
                  "doctype_value": DOCTYPE, "claims": [{"path": [NAMESPACE, CLAIM]}]}
        self._write(txid, "openid4vp-inputs.json", json.dumps(inputs, indent=1, sort_keys=True) + "\n")
        self._write(txid, "captured-at.txt", stamp(now) + "\n")
        self._write(txid, "verify.txt", "\n".join(lines) + "\ndone\n")
