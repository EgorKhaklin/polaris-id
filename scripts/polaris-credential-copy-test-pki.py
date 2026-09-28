#!/usr/bin/env python3
"""polaris-credential-copy-test-pki.py: a TEST certificate chain for one agency's wallet copies.

    python3 scripts/polaris-credential-copy-test-pki.py --agency 7 \\
        --issuer-url https://polaris.test/api/v1/oid4vci/7 --out /path/to/keys

Writes, into --out (the directory POLARIS_CREDENTIAL_COPY_KEYS_DIR names):

    <agency>.key.pem      the signing key, EC P-256, PKCS#8, mode 0600
    <agency>.chain.pem    the leaf certificate alone; the anchor stays out, as HAIP asks
    <agency>.anchor.pem   the test CA's certificate, to register with the wallet or verifier

The CA's private key is never written, so this CA can issue nothing else. Both certificates say
TEST in their names. This is for development, drills and the lab; a deployment's chain comes
from the agency's own PKI, and polaris_web/credential_copy_keys.py checks either kind the same
way. An existing key is never overwritten: remove the three files first.
"""

import argparse
import datetime
import os
import pathlib
import sys
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _usage(**on):
    names = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
             "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
    return x509.KeyUsage(**{n: on.get(n, False) for n in names})


def make(out: pathlib.Path, agency: int, issuer_url: str, days: int = 90) -> dict:
    host = urllib.parse.urlsplit(issuer_url).hostname
    if urllib.parse.urlsplit(issuer_url).scheme != "https" or not host:
        raise ValueError("--issuer-url must be an https URL with a host")
    paths = {kind: out / ("%d.%s.pem" % (agency, kind)) for kind in ("key", "chain", "anchor")}
    existing = [str(p) for p in paths.values() if p.exists()]
    if existing:
        raise FileExistsError("refusing to overwrite: " + ", ".join(existing))
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, "Polaris wallet-copy TEST CA, agency %d" % agency)])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=days + 1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(_usage(key_cert_sign=True, crl_sign=True), critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, "Polaris wallet-copy TEST issuer, agency %d" % agency)]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_usage(digital_signature=True), critical=True)
            .add_extension(x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(issuer_url), x509.DNSName(host)]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    fd = os.open(paths["key"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(leaf_key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    paths["chain"].write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    paths["anchor"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return {kind: str(p) for kind, p in paths.items()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("--agency", type=int, required=True)
    ap.add_argument("--issuer-url", required=True,
                    help="the credential issuer identifier, https://HOST/api/v1/oid4vci/AGENCY")
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--days", type=int, default=90, help="leaf validity (default 90)")
    args = ap.parse_args(argv)
    if args.agency < 1:
        ap.error("--agency must be a positive agency id")
    try:
        written = make(args.out, args.agency, args.issuer_url, args.days)
    except (ValueError, FileExistsError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    for kind in ("key", "chain", "anchor"):
        print("%-7s %s" % (kind, written[kind]))
    print("TEST chain: register %s with the wallet or verifier; never deploy it." % written["anchor"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
