# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""make_annexc_rows.py -- writes annexc-rows.json: ISO/IEC 18013-7 Annex C responses for two verifiers
to judge at one fixed instant, this repository's polaris_oid4vp (agree.py) and OID4VCgo's
mdocdcapi.VerifyResponse (annexc/main.go, through run.sh).

    python3 lab/interop/mdoc/witness-oid4vcgo/make_annexc_rows.py \\
        > lab/interop/mdoc/witness-oid4vcgo/annexc-rows.json

Run by hand, with cbor2 and cryptography installed. Every response holds fresh randomness (keys,
salts, the HPKE encapsulation), so a second run writes other bytes: the committed file is what was
judged, and agree.py prints each response's SHA-256. The rows, all judged at AT, each refused row
naming the stage it is refused at:

  ANNEXC-DETERMINISTIC-001 (refused at the document), ANNEXC-REAL-001 (refused at the open)
      the two outside vectors under packages/polaris-oid4vp/testdata/annex-c, copied field by field
      (agree.py holds each copy to its file and the file to its SHA-256). The first opens to a
      DeviceResponse with no document; the second is opened with a key its request does not carry.
  MINTED-VALID-AT-INSTANT
      test_mdoc.py's mDL, its device signature over test_annex_c.py's request's Annex C transcript,
      sealed to that request. Its certificates are test_mdoc.py's mDL profile with a countryName
      (ZZ, a user-assigned ISO 3166-1 code, the one mdoc-vectors.json uses) beside each common
      name, which Annex B makes mandatory in the IACA and the document signer. Its document signer
      is valid from a day before AT to thirty days after; its MSO is signed an hour before AT and
      valid to 2049. Valid at AT; on every run date after 2026-07-01 its document signer is the one
      date it falls outside.
  MINTED-DS-NOT-YET-VALID (refused at the document signer's validity)
      the same, its document signer valid from a day after AT to 2049, its MSO signed and valid from
      an hour after that: the signed date sits inside the document signer's validity, so the MSO
      starts after AT too. Not valid at AT, valid on the run date.
  CONTROL-ANOTHER-ORIGIN, CONTROL-ANOTHER-KEY, CONTROL-FLIPPED-CIPHERTEXT (refused at the open)
      MINTED-VALID-AT-INSTANT's response presented for another origin, opened with another key
      under the same EncryptionInfo, and with the last byte of its cipherText flipped.
"""
import base64
import datetime
import hashlib
import json
import pathlib
import sys
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
PACKAGE = REPO / "packages" / "polaris-oid4vp"
sys.path.insert(0, str(PACKAGE))

import cbor2  # noqa: E402
import cryptography  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from polaris_oid4vp.sdjwt import b64u_decode  # noqa: E402

import test_annex_c as ac  # noqa: E402
import test_mdoc as md  # noqa: E402

UTC = datetime.timezone.utc
AT = datetime.datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
FAR = datetime.datetime(2049, 12, 31, 0, 0, 0, tzinfo=UTC)
DAY = datetime.timedelta(days=1)
HOUR = datetime.timedelta(hours=1)
IACA_CN = "Annex C Lab IACA"
COUNTRY = "ZZ"
OTHER_ORIGIN = "https://other.example"
CLAIMS = {md.MDL_NS: {"family_name": "Mustermann", "age_over_21": True}}


def stamp(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def annex_b_name(cn):
    """test_mdoc.x509_name with the countryName Annex B makes mandatory in both certificates."""
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key_hex(key):
    return "%064x" % key.private_numbers().private_value


def outside(name, refused_at, session):
    v = ac.vector(name)  # held to its published SHA-256 first
    return {"id": v["id"], "kind": "outside", "expect": "refused", "refused_at": refused_at, "session": session,
            "source": {"path": "packages/polaris-oid4vp/testdata/annex-c/" + name,
                       "sha256": hashlib.sha256((ac.ANNEX_C / name).read_bytes()).hexdigest()},
            "origin": v["origin"], "doctype": v["expected"]["docType"],
            "elements": {md.MDL_NS: [v["expected"]["requestedElement"]]},
            "encryption_info": v["encryptionInfoB64"],
            "recipient_key_hex": "%064x" % int(v["recipientPrivateKeyHex"], 16),
            "response": v["encryptedResponseB64"]}


def minted(row_id, iaca_key, not_before, not_after, signed, refused_at=None):
    """One window row: its document signer valid from `not_before` to `not_after`, its MSO signed and
    valid from `signed` to FAR. Refused at `refused_at` when it names a stage, else accepted."""
    session, values = ac.request()
    ds_key, ds = md.make_ds(iaca_key, IACA_CN, not_before=not_before, not_after=not_after)
    device_response = ac.mint_for(values, ds=ds, ds_key=ds_key, signed=signed, valid_from=signed, valid_until=FAR)
    row = {"id": row_id, "kind": "window", "expect": "refused" if refused_at else "accepted", "session": "Session",
           "document_signer": {"not_before": stamp(not_before), "not_after": stamp(not_after)},
           "mso": {"signed": stamp(signed), "valid_from": stamp(signed), "valid_until": stamp(FAR)},
           "origin": ac.ORIGIN, "doctype": md.MDL, "elements": ac.ASKED,
           "encryption_info": values["encryptionInfo"], "recipient_key_hex": key_hex(session._recipient_key),
           "response": ac.seal(device_response, values)}
    if refused_at:
        row["refused_at"] = refused_at
    else:
        row["claims"] = CLAIMS
    return row


def control(of, row_id, **changes):
    row = {k: v for k, v in of.items() if k not in ("document_signer", "mso", "claims")}
    row.update({"id": row_id, "kind": "control", "of": of["id"], "expect": "refused", "refused_at": "open"},
               **changes)
    return row


def flipped(response):
    label, members = cbor2.loads(b64u_decode(response))
    ciphertext = bytearray(members["cipherText"])
    ciphertext[-1] ^= 0x01
    return ac.envelope(members["enc"], bytes(ciphertext), label=label)


def main():
    with mock.patch.object(md, "x509_name", annex_b_name):
        iaca_key, iaca = md.make_root(IACA_CN, not_before=AT - 30 * DAY, not_after=FAR)
        valid = minted("MINTED-VALID-AT-INSTANT", iaca_key, AT - DAY, AT + 30 * DAY, AT - HOUR)
        not_yet = minted("MINTED-DS-NOT-YET-VALID", iaca_key, AT + DAY, FAR, AT + DAY + HOUR,
                         refused_at="document_signer_validity")
    other_key = ec.generate_private_key(ec.SECP256R1())
    rows = [
        outside(ac.DETERMINISTIC, "document", "Session"),
        outside(ac.CAPTURED, "open", "fields"),
        valid,
        not_yet,
        control(valid, "CONTROL-ANOTHER-ORIGIN", origin=OTHER_ORIGIN),
        control(valid, "CONTROL-ANOTHER-KEY", session="fields", recipient_key_hex=key_hex(other_key)),
        control(valid, "CONTROL-FLIPPED-CIPHERTEXT", response=flipped(valid["response"])),
    ]
    out = {"about": "ISO/IEC 18013-7 Annex C rows for two verifiers, made by make_annexc_rows.py and "
                    "judged by agree.py and annexc/main.go at `at`",
           "at": stamp(AT), "max_skew_seconds": 300,
           "iaca_der_b64": base64.b64encode(iaca.public_bytes(serialization.Encoding.DER)).decode("ascii"),
           "iaca_doctypes": [md.MDL],
           "made_with": {"cryptography": cryptography.__version__},
           "rows": rows}
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
