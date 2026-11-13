# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Synthetic age-verification (eu.europa.ec.av.1) DeviceResponses for the [AVP] lab, made with our own TEST keys and
signed over the AVP SessionTranscript (redirect_uri: client id, no response encryption, so a null jwkThumbprint).

The pattern is lab/interop/negative-vectors/make_mdoc_vectors.py's mint(): keys derived from a public seed, ECDSA
with deterministic signing, so the same run writes the same bytes. Nothing here is real issuer material.

    python3 make_vectors.py OUTDIR      # writes OUTDIR/manifest.json and one folder per case
"""
import base64
import datetime
import hashlib
import json
import pathlib
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = datetime.timezone.utc
SEED = "polaris-altid-avp-lab/"
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

DOCTYPE = "eu.europa.ec.av.1"
NAMESPACE = "eu.europa.ec.av.1"
OTHER_DOCTYPE = "org.iso.18013.5.1.mDL"
AT = datetime.datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)          # the instant every case is judged at
AT_MSO_EXPIRED = datetime.datetime(2026, 12, 2, 12, 0, 0, tzinfo=UTC)  # after validUntil, the certificates valid
AT_CERT_EXPIRED = datetime.datetime(2027, 2, 1, 12, 0, 0, tzinfo=UTC)  # after every certificate's notAfter
T0 = datetime.datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime.datetime(2027, 1, 1, tzinfo=UTC)
MSO_SIGNED, MSO_VALID_UNTIL = "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


TXID = b64u(hashlib.sha256((SEED + "txid").encode()).digest())
RESPONSE_URI = "https://avp-lab.example/response/" + TXID
NONCE = b64u(hashlib.sha256((SEED + "nonce").encode()).digest()[:16])
AVP_INPUTS = {"client_id": "redirect_uri:" + RESPONSE_URI, "nonce": NONCE, "response_uri": RESPONSE_URI,
              "response_mode": "direct_post", "encryption_jwk": None}


def _key(label):
    d = int.from_bytes(hashlib.sha256((SEED + "key/" + label).encode()).digest(), "big") % (_P256_N - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


T13_K, TWIN_K, ROOT_K, INT_K = _key("table13-shape"), _key("table13-twin"), _key("root"), _key("intermediate")
LEAF_R_K, LEAF_I_K, DEVICE_K, OTHER_DEVICE_K, OTHER_K = (
    _key("leaf-under-root"), _key("leaf-under-intermediate"), _key("device"), _key("device-other"), _key("other"))
ENC_K = _key("encryption")


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, key, issuer, issuer_key, serial, *, ca, table13_shape=False):
    """A certificate. table13_shape: the extensions the guide's Table 13 test certificate carries, as openssl prints
    them (Key Usage critical Digital Signature and Non Repudiation; Basic Constraints CA:FALSE; Extended Key Usage
    serverAuth and clientAuth; an Authority Key Identifier equal to the Subject Key Identifier)."""
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(key.public_key()).serial_number(serial).not_valid_before(T0).not_valid_after(T1)
         .add_extension(ski, critical=False))
    if table13_shape:
        b = b.add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                            critical=False)
    elif ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key())), critical=False)
    return b.sign(issuer_key, hashes.SHA256(), ecdsa_deterministic=True)


T13 = _cert("AVP Lab Table 13-shape Signer", T13_K, "AVP Lab Table 13-shape Signer", T13_K, 13, ca=False,
            table13_shape=True)
TWIN = _cert("AVP Lab Table 13-shape Signer", TWIN_K, "AVP Lab Table 13-shape Signer", TWIN_K, 14, ca=False,
             table13_shape=True)  # the same subject, another key
ROOT = _cert("AVP Lab Root", ROOT_K, "AVP Lab Root", ROOT_K, 1, ca=True)
INT = _cert("AVP Lab Intermediate", INT_K, "AVP Lab Root", ROOT_K, 2, ca=True)
LEAF_R = _cert("AVP Lab Signer under the root", LEAF_R_K, "AVP Lab Root", ROOT_K, 3, ca=False)
LEAF_I = _cert("AVP Lab Signer under the intermediate", LEAF_I_K, "AVP Lab Intermediate", INT_K, 4, ca=False)

# The Table 13-shape certificate with the last byte of its signature changed: self-issued (subject equals issuer)
# and still the key that signs the MSO, but not self-signed.
_T13_DER = T13.public_bytes(serialization.Encoding.DER)
T13_BROKEN = x509.load_der_x509_certificate(_T13_DER[:-1] + bytes([_T13_DER[-1] ^ 1]))

CERTS = {"table13-shape": T13, "twin": TWIN, "root": ROOT, "intermediate": INT, "leaf-under-root": LEAF_R,
         "leaf-under-intermediate": LEAF_I, "table13-shape-signature-broken": T13_BROKEN}
# x5chain (leaf first, as sent) and the key that signs the MSO.
CHAINS = {
    "table13": ([T13], T13_K),
    "table13-signature-broken": ([T13_BROKEN], T13_K),
    "leaf-root": ([LEAF_R, ROOT], LEAF_R_K),
    "leaf-intermediate": ([LEAF_I, INT], LEAF_I_K),
    "leaf-alone": ([LEAF_R], LEAF_R_K),
    "unordered": ([ROOT, LEAF_R], LEAF_R_K),
    "twin": ([TWIN], TWIN_K),
    "other-signer": ([T13], OTHER_K),  # the first certificate did not sign the MSO
    "empty": ([], T13_K),
}


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def sha256_hex(cert):
    return hashlib.sha256(der(cert)).hexdigest()


def _es256(key, data):
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _tag24(inner):
    return cbor2.CBORTag(24, inner)


def _cose_key(key):
    n = key.public_key().public_numbers()
    return {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def jwk_thumbprint(key):
    """RFC 7638 over the EC public JWK, as verify_mdoc.jwk_thumbprint computes it."""
    n = key.public_key().public_numbers()
    jwk = {"crv": "P-256", "kty": "EC", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    return hashlib.sha256(json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()).digest()


def transcript(inputs, thumbprint=None):
    """OpenID4VP 1.0 B.2.6.1, with the thumbprint given (None for an unencrypted response)."""
    info = cbor2.dumps([inputs["client_id"], inputs["nonce"], thumbprint, inputs["response_uri"]])
    return [None, None, ["OpenID4VPHandover", hashlib.sha256(info).digest()]]


ES256 = cbor2.dumps({1: -7})


def mint(*, chain="table13", x5_form="array", doc_type=DOCTYPE, mso_doc_type=None, age=True, status_element=False,
         signed_transcript=None, device_signer=DEVICE_K, n_documents=1, response_status=0):
    """One DeviceResponse (CBOR bytes). `chain` names CHAINS; `x5_form` is "bstr" (one certificate as a byte string,
    as Appendix F sends it) or "array"; `age` is the age_over_18 value, or None for no such element; `status_element`
    puts a status element in the MSO; `signed_transcript` is the SessionTranscript the device signature is made over
    (default: the AVP one); `n_documents` copies of the document; `response_status` the DeviceResponse status."""
    certs, issuer_key = CHAINS[chain]
    if x5_form == "bstr":
        if len(certs) != 1:
            raise ValueError("a bstr x5chain holds one certificate")
        x5 = der(certs[0])
    else:
        x5 = [der(c) for c in certs]
    elements = [] if age is None else [("age_over_18", age)]
    items = [_tag24(cbor2.dumps({"digestID": i, "random": hashlib.sha256((SEED + "random/" + n).encode()).digest(),
                                 "elementIdentifier": n, "elementValue": v})) for i, (n, v) in enumerate(elements)]
    if not items:  # the MSO still digests something, so only the claim is missing
        items = [_tag24(cbor2.dumps({"digestID": 0, "random": hashlib.sha256((SEED + "random/x").encode()).digest(),
                                     "elementIdentifier": "age_over_21", "elementValue": True}))]
    digests = {cbor2.loads(it.value)["digestID"]: hashlib.sha256(cbor2.dumps(it)).digest() for it in items}
    mso = {"version": "1.0", "digestAlgorithm": "SHA-256", "valueDigests": {NAMESPACE: digests},
           "deviceKeyInfo": {"deviceKey": _cose_key(DEVICE_K)}, "docType": mso_doc_type or doc_type,
           "validityInfo": {"signed": cbor2.CBORTag(0, MSO_SIGNED), "validFrom": cbor2.CBORTag(0, MSO_SIGNED),
                            "validUntil": cbor2.CBORTag(0, MSO_VALID_UNTIL)}}
    if status_element:
        mso["status"] = {"status_list": {"idx": 7, "uri": "https://avp-lab.example/status/1"}}
    payload = cbor2.dumps(_tag24(cbor2.dumps(mso)))
    issuer_auth = [ES256, {33: x5}, payload, _es256(issuer_key, cbor2.dumps(["Signature1", ES256, b"", payload]))]
    device_ns = _tag24(cbor2.dumps({}))
    st = signed_transcript if signed_transcript is not None else transcript(AVP_INPUTS)
    auth = cbor2.dumps(_tag24(cbor2.dumps(["DeviceAuthentication", st, doc_type, device_ns])))
    dsig = [ES256, {}, None, _es256(device_signer, cbor2.dumps(["Signature1", ES256, b"", auth]))]
    doc = {"docType": doc_type, "issuerSigned": {"nameSpaces": {NAMESPACE: items}, "issuerAuth": issuer_auth},
           "deviceSigned": {"nameSpaces": device_ns, "deviceAuth": {"deviceSignature": dsig}}}
    return cbor2.dumps({"version": "1.0", "documents": [doc] * n_documents, "status": response_status})


# name: (mint arguments, pinned certificates, instant, expected). expected is "satisfied", "not satisfied", or the
# refused check's name, as avp.py names it.
CASES = {
    "table13-bstr": ({"x5_form": "bstr"}, ["table13-shape"], AT, "satisfied"),
    "table13-array": ({}, ["table13-shape"], AT, "satisfied"),
    "leaf-root": ({"chain": "leaf-root"}, ["root"], AT, "satisfied"),
    "age-false": ({"age": False}, ["table13-shape"], AT, "not satisfied"),
    "age-missing": ({"age": None}, ["table13-shape"], AT, "not satisfied"),
    "two-documents": ({"n_documents": 2}, ["table13-shape"], AT, "device response"),
    "no-documents": ({"n_documents": 0}, ["table13-shape"], AT, "device response"),
    "status-10": ({"response_status": 10}, ["table13-shape"], AT, "device response"),
    "end-at-intermediate": ({"chain": "leaf-intermediate"}, ["intermediate"], AT, "trust list"),
    "pinned-leaf-alone": ({"chain": "leaf-alone"}, ["leaf-under-root"], AT, "trust list"),
    "unordered": ({"chain": "unordered"}, ["root"], AT, "trust list"),
    "self-signature-broken": ({"chain": "table13-signature-broken"}, ["table13-shape-signature-broken"], AT,
                              "trust list"),
    "empty-x5chain": ({"chain": "empty"}, ["table13-shape"], AT, "issuer chain"),
    "first-did-not-sign": ({"chain": "other-signer"}, ["table13-shape"], AT, "issuer signature"),
    "same-subject-other-key": ({"chain": "twin"}, ["table13-shape"], AT, "trust list"),
    "certificate-expired": ({}, ["table13-shape"], AT_CERT_EXPIRED, "issuer chain"),
    "mso-expired": ({}, ["table13-shape"], AT_MSO_EXPIRED, "validity"),
    "mso-doctype-other": ({"mso_doc_type": OTHER_DOCTYPE}, ["table13-shape"], AT, "docType"),
    "document-doctype-other": ({"doc_type": OTHER_DOCTYPE}, ["table13-shape"], AT, "requested docType"),
    "status-element": ({"status_element": True}, ["table13-shape"], AT, "status"),
    "device-other-key": ({"device_signer": OTHER_DEVICE_K}, ["table13-shape"], AT, "device signature"),
    "signed-bare-client-id": ({"signed_transcript": transcript(dict(AVP_INPUTS, client_id=RESPONSE_URI))},
                              ["table13-shape"], AT, "device signature"),
    "signed-with-thumbprint": ({"signed_transcript": transcript(AVP_INPUTS, jwk_thumbprint(ENC_K))},
                               ["table13-shape"], AT, "device signature"),
}


def write(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "certs").mkdir(exist_ok=True)
    for name, cert in CERTS.items():
        (out / "certs" / (name + ".pem")).write_text(pem(cert))
    manifest = {"note": "TEST material from the public seed %r; nothing here is real issuer material" % SEED,
                "inputs": dict(AVP_INPUTS, doctype_value=DOCTYPE, claims=[{"path": [NAMESPACE, "age_over_18"]}]),
                "cases": []}
    for name, (kwargs, pins, at, expected) in CASES.items():
        d = out / name
        d.mkdir(exist_ok=True)
        (d / "device-response.cbor").write_bytes(mint(**kwargs))
        manifest["cases"].append({"name": name, "pins": pins, "pins_sha256": [sha256_hex(CERTS[p]) for p in pins],
                                  "at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "expected": expected})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: make_vectors.py OUTDIR")
    m = write(sys.argv[1])
    print("wrote %d cases to %s" % (len(m["cases"]), sys.argv[1]))
    print("done")
