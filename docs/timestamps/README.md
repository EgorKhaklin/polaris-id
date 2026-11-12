# Timestamps

`polaris-timestamps-2026-11-07.sha256` lists the SHA-256 of the five paper PDFs in `docs/paper/` and of the seven
`v1.0.0` release assets. Two independent RFC 3161 time-stamping authorities, DigiCert and Sectigo, each signed the
list's hash on 2026-11-07; their replies are the two `.tsr` files. A reply shows the listed files existed by the time it
states.

Check a reply with OpenSSL 3 from this directory (on macOS, Homebrew's openssl@3: the system openssl is LibreSSL; the
CA bundle path varies by system):

    openssl ts -verify -data polaris-timestamps-2026-11-07.sha256 \
      -in polaris-timestamps-2026-11-07.sha256.digicert.tsr -CAfile /etc/ssl/cert.pem
    openssl ts -reply -in polaris-timestamps-2026-11-07.sha256.digicert.tsr -text | grep 'Time stamp'

The same two commands with `sectigo` check the second reply. Then check the PDFs against the list from the repository
root:

    grep ' docs/paper/' docs/timestamps/polaris-timestamps-2026-11-07.sha256 | sha256sum -c -

The `v1.0.0/` lines name the release assets; download them into a `v1.0.0/` directory to check them the same way.
