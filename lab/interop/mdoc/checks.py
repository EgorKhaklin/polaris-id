#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The capture, verified by verify_mdoc.py and by isomdl-uniffi, genuine and with four negatives.

    python3 -I checks.py CAPTURE_DIR ISOMDL_PYTHON

Cases (each run through both verifiers; ours must give the expected verdict):
  genuine          VERIFIED, or for an mDL whose DS certificate lacks SubjectKeyIdentifier or the
                   id-mdl-ds EKU, REFUSED at the DS profile;
  profile off      the genuine capture with the DS profile not enforced: a diagnostic of every
                   other check, not a verdict;
  null thumbprint  (direct_post.jwt captures) the transcript isomdl-uniffi builds, with no JWK
                   thumbprint: must refuse at the device signature;
  no root, unrelated root, flipped MSO sig, wrong nonce: must refuse;
  bad DER cert, bad protected header: one byte changed in place: must refuse, not raise;
then, on ours only: ds_profile on synthetic certificates (mDL with both, without the EKU, without the
SKI; PID with neither), an off-curve deviceKey, and the OpenID4VP 1.0 B.2.6.1 example vector.
Exit 0 only if every case gave the expected verdict. isomdl-uniffi's verdicts are reported, not
asserted.
"""
import datetime
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_mdoc", HERE / "verify_mdoc.py")
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


def unrelated_root(path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated test IACA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def mutate(src, dst, pick, offset, value=None):
    """Copy the capture with one byte of the response changed in place: the byte at `offset` (from
    the end if negative) of the field `pick` selects, XORed with 1, or set to `value`."""
    shutil.copytree(src, dst)
    buf = bytearray((src / "device-response.cbor").read_bytes())
    field = pick(vm.load_all(bytes(buf))["documents"][0])
    at = bytes(buf).find(field)
    if not field or at < 0 or bytes(buf).count(field) != 1:
        sys.exit("cannot locate the field uniquely")
    i = at + (offset if offset >= 0 else len(field) + offset)
    buf[i] = (buf[i] ^ 0x01) if value is None else value
    (dst / "device-response.cbor").write_bytes(bytes(buf))


def issuer_auth(doc):
    return doc["issuerSigned"]["issuerAuth"]


# The IssuerAuth protected header is the same few bytes as the device signature's, so it is found in
# context: the COSE_Sign1 array head, the protected bstr, and the unprotected map holding x5chain (33).
PROT_PREFIX = b"\x84\x43"


def protected_in_context(doc):
    prot = issuer_auth(doc)[0]
    if len(prot) != 3:
        sys.exit("the IssuerAuth protected header is not 3 bytes; adjust PROT_PREFIX")
    # ... and the head of the x5chain value: the device signature's unprotected map also has a label
    # 33 (walt.id writes an empty x5chain array there), so the issuer's is told apart by its value.
    return PROT_PREFIX + prot + b"\xa1\x18\x21" + vm.cbor2.dumps(issuer_auth(doc)[1][33])[:1]


def first_cert(doc):
    x5 = issuer_auth(doc)[1][33]
    return x5 if isinstance(x5, bytes) else x5[0]


def ds_cert(ski, eku):
    """A DS certificate under a fresh IACA, with or without SubjectKeyIdentifier and id-mdl-ds EKU."""
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test DS")]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test IACA")]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    if ski:
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier(vm.ID_MDL_DS)]), critical=True)
    return b.sign(ca_key, hashes.SHA256())


def profile_units():
    """ds_profile on synthetic DS certificates: it passes both extensions for an mDL, refuses either
    missing for an mDL, and reports (does not refuse) them missing for the PID."""
    mdl, pid = "org.iso.18013.5.1.mDL", "eu.europa.ec.eudi.pid.1"
    units = [("mDL, SKI and EKU", ds_cert(True, True), mdl, "PASS"),
             ("mDL, no EKU", ds_cert(True, False), mdl, "REFUSED"),
             ("mDL, no SKI", ds_cert(False, True), mdl, "REFUSED"),
             ("PID, neither", ds_cert(False, False), pid, "PASS")]
    fail = 0
    for name, cert, doc_type, expect in units:
        try:
            vm.ds_profile(cert, doc_type, True)
            got = "PASS"
        except vm.Refused as e:
            got = "REFUSED %s" % e
        ok = got.startswith(expect)
        fail |= not ok
        print("== ds profile unit, %s (expect %s): %s\n   ours:  %s" % (name, expect, "ok" if ok else "FAIL", got))
    return fail


def ours(capture, roots, nonce=None, null_thumbprint=False, profile=True):
    response, inputs = vm.load_capture(capture)
    if nonce:
        inputs = dict(inputs, nonce=nonce)
    if null_thumbprint:  # the transcript isomdl-uniffi builds: no JWK thumbprint
        inputs = dict(inputs, response_mode="direct_post", encryption_jwk=None, wallet_session_transcript_hex=None)
    at_text = (capture / "captured-at.txt").read_text().strip()
    at = datetime.datetime.fromisoformat(at_text.replace("Z", "+00:00"))
    roots = [x509.load_pem_x509_certificate(pathlib.Path(r).read_bytes()) for r in roots]
    steps = []
    try:
        vm.verify(response, inputs, roots, at, log=lambda c, d: steps.append(c), enforce_profile=profile)
        return "VERIFIED", steps
    except vm.Refused as e:
        return "REFUSED %s" % e, steps


def theirs(isomdl_python, capture, roots, nonce=None):
    cmd = [isomdl_python, "-I", str(HERE / "witness_isomdl.py"), str(capture)]
    for r in roots:
        cmd += ["--root", str(r)]
    if nonce:
        cmd += ["--nonce", nonce]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if p.returncode != 0 or not p.stdout.strip():
        return {"exception": "exit %d: %s" % (p.returncode, p.stderr.strip()[-300:])}
    return json.loads(p.stdout.strip().splitlines()[-1])


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    capture, isomdl_python = pathlib.Path(sys.argv[1]).resolve(), sys.argv[2]
    if not (capture / "device-response.cbor").is_file() or not (capture / "device-response.cbor").stat().st_size:
        sys.exit("no capture in %s" % capture)
    root = capture / "iaca-root.pem"
    tmp = pathlib.Path(tempfile.mkdtemp())
    unrelated_root(tmp / "unrelated.pem")
    mutate(capture, tmp / "flipped", lambda d: issuer_auth(d)[3], -1)
    mutate(capture, tmp / "bad-der", first_cert, 0, 0x31)  # the certificate's SEQUENCE tag made a SET
    mutate(capture, tmp / "bad-header", protected_in_context, len(PROT_PREFIX), 0xFF)  # the protected map's head made a break
    response, inputs = vm.load_capture(capture)
    wrong = "x" + inputs["nonce"]
    doc_type = vm.load_all(response)["documents"][0]["docType"]
    # The EU issuer's DS certificate has no SubjectKeyIdentifier and no id-mdl-ds EKU: an mDL from it
    # is refused at the DS profile, and the "profile off" diagnostic shows every other check.
    genuine = "REFUSED ds profile" if doc_type in vm.PROFILE_DOCTYPES else "VERIFIED"
    # (name, capture, roots, nonce, null thumbprint, enforce profile, expected verdict prefix)
    cases = [
        ("genuine", capture, [root], None, False, True, genuine),
        ("profile off (diagnostic, not a verdict)", capture, [root], None, False, False, "VERIFIED"),
        ("no root", capture, [], None, False, True, "REFUSED issuer chain"),
        ("unrelated root", capture, [tmp / "unrelated.pem"], None, False, True, "REFUSED issuer chain"),
        ("flipped MSO sig", tmp / "flipped", [root], None, False, False, "REFUSED issuer signature"),
        ("wrong nonce", capture, [root], wrong, False, False, "REFUSED device signature"),
        ("bad DER x5chain cert", tmp / "bad-der", [root], None, False, True, "REFUSED issuer chain"),
        ("bad protected header", tmp / "bad-header", [root], None, False, True, "REFUSED issuer signature"),
    ]
    if inputs.get("response_mode") == "direct_post.jwt":
        cases.insert(2, ("null thumbprint (isomdl's transcript)", capture, [root], None, True, False,
                         "REFUSED device signature"))
    if not cases:
        sys.exit("no cases")
    fail = 0
    for name, cap, roots, nonce, null, profile, expect in cases:
        verdict, steps = ours(cap, roots, nonce, null, profile)
        w = theirs(isomdl_python, cap, roots, nonce)
        ok = verdict.startswith(expect)
        fail |= not ok
        print("== %s (expect %s%s): %s" % (name, expect, "" if profile else "; DS profile not enforced",
                                           "ok" if ok else "FAIL"))
        print("   ours:  %s" % verdict)
        print("          checks passed: %s" % (", ".join(steps) or "none"))
        print("   isomdl: %s" % json.dumps(w))
    fail |= profile_units()
    # A deviceKey off its curve cannot reach the response without breaking the issuer signature over
    # the MSO, so it is checked on the parser: it must refuse, not raise.
    try:
        vm.cose_key({1: 2, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
        off = "ACCEPTED"
    except vm.Refused as e:
        off = "REFUSED %s" % e
    fail |= not off.startswith("REFUSED")
    print("== off-curve deviceKey (cose_key unit, expect REFUSED): %s" % ("ok" if off.startswith("REFUSED") else "FAIL"))
    print("   ours:  %s" % off)
    # The SessionTranscript construction against the specification's own example.
    try:
        vm.check_spec_vector()
        spec = "reproduces the OpenID4VP 1.0 B.2.6.1 example SessionTranscript byte for byte"
    except vm.Refused as e:
        spec, fail = "FAILED %s" % e, 1
    print("== spec vector: %s" % spec)
    shutil.rmtree(tmp)
    print("RESULT: %s" % ("as expected" if not fail else "FAILED"))
    print("done")
    return fail


if __name__ == "__main__":
    sys.exit(main())
