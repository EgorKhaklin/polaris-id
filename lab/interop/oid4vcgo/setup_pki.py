"""Test PKI and config for OID4VCgo's conformance-wallet-vp presenting to polaris-oid4vp.

Writes, into the directory given:
  issuer-ca.pem         the CA polaris-oid4vp is told to trust (--issuer-trust-anchor)
  other-ca.pem          an unrelated CA, for the control that the anchor is what decides
  config.json           the wallet's config: its TLS listener, the credential issuer's key and
                        CA-issued leaf (x5c), the holder key, the vct and the claims it presents
Only public material goes anywhere but config.json, which the wallet reads.
"""
import datetime
import json
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
now = datetime.datetime.now(datetime.timezone.utc)


def key():
    return ec.generate_private_key(ec.SECP256R1())


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption()).decode()


def pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM).decode()


def ca(name):
    k = key()
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                      crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
         .sign(k, hashes.SHA256()))
    return k, c


ca_key, ca_cert = ca("oid4vcgo interop issuer CA")
_, other_cert = ca("an unrelated CA")

issuer_key = key()
issuer_leaf = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oid4vcgo interop credential issuer")]))
               .issuer_name(ca_cert.subject).public_key(issuer_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))

tls_key = key()
tls_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
tls_cert = (x509.CertificateBuilder().subject_name(tls_name).issuer_name(tls_name).public_key(tls_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(tls_key, hashes.SHA256()))

(out / "issuer-ca.pem").write_text(pem_cert(ca_cert))
(out / "other-ca.pem").write_text(pem_cert(other_cert))
(out / "config.json").write_text(json.dumps({
    "listen_addr": ":8443",
    "tls_certificate_pem": pem_cert(tls_cert), "tls_private_key_pem": pem_key(tls_key),
    "credential_issuer_private_key_pem": pem_key(issuer_key),
    "credential_issuer_certificate_pem": pem_cert(issuer_leaf),
    "holder_private_key_pem": pem_key(key()),
    "vct": "urn:eudi:pid:1",
    "claims": {"given_name": "Ada", "family_name": "Lovelace"},
}, indent=2))
print("wrote issuer-ca.pem, other-ca.pem, config.json to", out)
