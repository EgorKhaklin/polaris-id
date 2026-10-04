# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The walk's test certificates, made with `cryptography`. These keys are for testing.

  pki.py tls HOST OUT        a self-signed TLS certificate for HOST: OUT.pem, OUT-key.pem
  pki.py ca NAME OUT         an issuer root CA: OUT.pem, OUT-key.pem
  pki.py sign CA CSR HOST OUT
                             certify the key in CSR (made by Procivis) as an issuer signing
                             certificate under CA, naming HOST: OUT.pem
"""
import datetime
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = datetime.datetime.now(datetime.timezone.utc)


def _write(out, cert, key=None):
    with open(out + ".pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        with open(out + "-key.pem", "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))


def _builder(subject, issuer, public_key, days):
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(minutes=5))
            .not_valid_after(NOW + datetime.timedelta(days=days))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False))


def tls(host, out):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (_builder(name, name, key.public_key(), 90)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    _write(out, cert, key)


def ca(name, out):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (_builder(subject, subject, key.public_key(), 365)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    _write(out, cert, key)


def sign(ca_prefix, csr_path, host, out):
    with open(ca_prefix + ".pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_prefix + "-key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), None)
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())
    if not csr.is_signature_valid:
        sys.exit("the CSR's signature does not verify")
    cert = (_builder(csr.subject, ca_cert.subject, csr.public_key(), 90)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write(out, cert)


if __name__ == "__main__":
    command, args = sys.argv[1], sys.argv[2:]
    {"tls": tls, "ca": ca, "sign": sign}[command](*args)
