# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""decide.py: Token Status Lists made outside Polaris, decided by polaris-oid4vp.

    python decide.py DRAFT_TXT AUTHORS_UTIL_PY OWF_JSON

Every status below goes through `polaris_oid4vp.status.decide`, the function a verifier calls
on a fetched list. Three sources, none of them Polaris:

1. draft-ietf-oauth-status-list-21: the byte arrays of Section 4.2 and the test vectors of
   Appendix C (1, 2, 4 and 8 bits, 2^20 entries each). They carry no signature, so each `lst` is
   wrapped in a token this script signs with a key of its own; decide() then decodes it exactly
   as it decodes a fetched list.
2. The draft's signed example Status List Token (Section 8.2), checked with the example key
   the draft's authors publish in their repository (src/util.py).
3. Tokens signed with the OpenWallet Foundation's @sd-jwt/jwt-status-list (owf/mint.mjs).

Then the controls. Exits 0 only if every status matches and every control is refused with the
expected code.
"""
import base64
import json
import random
import re
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from polaris_oid4vp import status as S

NOW = int(time.time())
failures = []


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def es256_verifier(public_key):
    def verify(signing_input, signature, header):
        if len(signature) != 64:
            return False
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                         int.from_bytes(signature[32:], "big"))
        try:
            public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True
    return verify


def public_key_from(x, y):
    return ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_decode(x), "big"),
                                         int.from_bytes(b64u_decode(y), "big"),
                                         ec.SECP256R1()).public_key()


def authority(issuer, uri, public_key, why):
    return S.StatedAuthority().state(credential_issuer=issuer, status_uri=uri,
                                     verify=es256_verifier(public_key), why=why)


def check(label, token, uri, issuer, grant, expected):
    """decide() at every (index, value) in `expected`; one line of output."""
    wrong = []
    for index, value in expected:
        v = S.decide(token, index=index, expected_uri=uri, authority=grant, now=NOW,
                     credential_issuer=issuer)
        if not v["checked"] or v["status"] != value:
            wrong.append((index, value, v["status"], v["code"], v["reason"]))
    if wrong:
        failures.append(label)
        index, value, got, code, reason = wrong[0]
        print("  FAIL   %s: %d of %d wrong; index %d expected %d, got %r (%s: %s)"
              % (label, len(wrong), len(expected), index, value, got, code, reason))
    else:
        print("  ok     %s: %d statuses match" % (label, len(expected)))


def control(label, verdict, code):
    if verdict["checked"] or verdict["code"] != code:
        failures.append("control: " + label)
        print("  FAIL   control %s: expected refusal %r, got checked=%r code=%r"
              % (label, code, verdict["checked"], verdict["code"]))
    else:
        print("  ok     control %s: refused (%s)" % (label, code))


# --------------------------------------------------------------------------- the draft text

def draft_lines(path):
    """The draft without its page furniture (running headers, footers, form feeds)."""
    keep = []
    for line in open(path, encoding="utf-8").read().replace("\f", "").splitlines():
        if re.match(r"^(Looker, et al\.|Internet-Draft)\s", line):
            continue
        keep.append(line)
    return keep


def block_after(lines, start, opener, closer):
    """The text from the first line equal to `opener` (stripped) through `closer`, joined."""
    i = start
    while lines[i].strip() != opener:
        i += 1
    text = []
    while True:
        text.append(lines[i].strip())
        if lines[i].strip() == closer:
            return "".join(text), i
        i += 1


def statuses_from_bytes(array, bits):
    per_byte = 8 // bits
    mask = (1 << bits) - 1
    return [(array[i // per_byte] >> ((i % per_byte) * bits)) & mask
            for i in range(len(array) * per_byte)]


def own_token(bits, lst, uri, private_key):
    header = {"alg": "ES256", "typ": "statuslist+jwt"}
    payload = {"sub": uri, "iat": NOW, "exp": NOW + 3600,
               "status_list": {"bits": bits, "lst": lst}}
    signing_input = (b64u(json.dumps(header).encode()) + "." +
                     b64u(json.dumps(payload).encode())).encode()
    r, s = utils.decode_dss_signature(private_key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return signing_input.decode() + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def draft_vectors(lines):
    """(label, bits, expected statuses as {index: value} or a list, lst, size) from the draft."""
    found = []
    # Section 4.2: a stated byte array, then its JSON encoding.
    section = next(i for i, l in enumerate(lines) if l.startswith("4.2.  Status List in JSON"))
    end = next(i for i, l in enumerate(lines) if l.startswith("4.3.  "))
    i = section
    while True:
        at = next((j for j in range(i, end) if lines[j].strip() == "byte array:"), None)
        if at is None:
            break
        array_line = next(lines[j] for j in range(at + 1, end) if lines[j].strip())
        array = bytes(int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", array_line))
        text, i = block_after(lines, at, "{", "}")
        doc = json.loads(text)
        found.append(("draft 4.2, %d-bit byte array %s" % (doc["bits"], array_line.strip()),
                      doc["bits"], statuses_from_bytes(array, doc["bits"]), doc["lst"],
                      len(array) * (8 // doc["bits"])))
    # Appendix C: listed statuses (all others are 0), then the JSON encoding; 2^20 entries.
    heads = [i for i, l in enumerate(lines) if re.match(r"^C\.\d\.\s+\d-bit Status List", l)]
    for n, head in enumerate(heads):
        stop = heads[n + 1] if n + 1 < len(heads) else len(lines)
        bits = int(re.match(r"^C\.\d\.\s+(\d)-bit", lines[head]).group(1))
        listed = {}
        for line in lines[head:stop]:
            m = re.match(r"^\s*status\[(\d+)\]\s*=\s*0b([01]+)\s*$", line)
            if m:
                listed[int(m.group(1))] = int(m.group(2), 2)
        json_at = next(i for i in range(head, stop) if lines[i].strip() == "JSON encoding:")
        text, _ = block_after(lines, json_at, "{", "}")
        doc = json.loads(text)
        assert doc["bits"] == bits, (doc["bits"], bits)
        found.append(("draft %s, %d-bit, 2^20 entries" % (lines[head].split()[0].rstrip("."), bits),
                      bits, listed, doc["lst"], 1 << 20))
    return found


def signed_example(lines):
    """The compact Status List Token of the draft's Section 8.2 response example."""
    at = next(i for i, l in enumerate(lines)
              if l.strip() == "Content-Type: application/statuslist+jwt")
    parts, i = [], at + 1
    while not lines[i].strip():
        i += 1
    while lines[i].strip():
        parts.append(lines[i].strip())
        i += 1
    return "".join(parts)


def main(draft_path, util_path, owf_path):
    lines = draft_lines(draft_path)
    rng = random.Random(20261004)
    own_key = ec.generate_private_key(ec.SECP256R1())
    stranger_key = ec.generate_private_key(ec.SECP256R1()).public_key()

    print("draft-ietf-oauth-status-list-21, Section 4.2 and Appendix C (wrapped in this script's own token)")
    vectors = draft_vectors(lines)
    if len(vectors) != 6:
        failures.append("the draft parse")
        print("  FAIL   expected 2 byte arrays and 4 test vectors in the draft, found %d" % len(vectors))
    for n, (label, bits, statuses, lst, size) in enumerate(vectors):
        uri = "https://draft.example/statuslists/%d" % n
        token = own_token(bits, lst, uri, own_key)
        grant = authority("https://draft.example", uri, own_key.public_key(),
                          "this script's own key: the draft's vectors carry no signature")
        if isinstance(statuses, list):
            expected = list(enumerate(statuses))
        else:
            others = set()
            while len(others) < 500:
                index = rng.randrange(size)
                if index not in statuses:
                    others.add(index)
            expected = sorted(statuses.items()) + [(i, 0) for i in sorted(others)]
            if size - 1 not in statuses:
                expected.append((size - 1, 0))
            label += " (%d listed + %d others)" % (len(statuses), len(expected) - len(statuses))
        check(label, token, uri, "https://draft.example", grant, expected)
        if n == len(vectors) - 1:
            control("index past the end of %s" % label.split(" (")[0],
                    S.decide(token, index=size, expected_uri=uri, authority=grant, now=NOW,
                             credential_issuer="https://draft.example"), "index")

    print("the draft's signed example (Section 8.2), with the authors' published example key")
    util = open(util_path, encoding="utf-8").read()
    x = re.search(r'"x":\s*"([A-Za-z0-9_-]+)"', util).group(1)
    y = re.search(r'"y":\s*"([A-Za-z0-9_-]+)"', util).group(1)
    example = signed_example(lines)
    header = json.loads(b64u_decode(example.split(".")[0]))
    claims = json.loads(b64u_decode(example.split(".")[1]))
    grant = authority(claims["iss"], claims["sub"], public_key_from(x, y),
                      "the example key the draft's authors publish (kid %s)" % header.get("kid"))
    one_bit_example = statuses_from_bytes(bytes([0xB9, 0xA3]), 1)      # the draft's Section 4.1
    check("example token, kid %s, iat %s" % (header.get("kid"),
                                              time.strftime("%Y-%m-%d", time.gmtime(claims["iat"]))),
          example, claims["sub"], claims["iss"], grant, list(enumerate(one_bit_example)))
    v = S.decide(example, index=0, expected_uri=claims["sub"], authority=grant, now=NOW,
                 credential_issuer=claims["iss"])
    print("         (stale=%s: its iat is %ds old against a ttl of %ds; reported, not refused)"
          % (v["stale"], NOW - claims["iat"], claims["ttl"]))
    control("the example token under an unrelated key",
            S.decide(example, index=0, expected_uri=claims["sub"],
                     authority=authority(claims["iss"], claims["sub"], stranger_key, "a stranger"),
                     now=NOW, credential_issuer=claims["iss"]), "signature")

    owf = json.load(open(owf_path, encoding="utf-8"))
    print("tokens signed with the OpenWallet Foundation's %s" % owf["library"])
    trusted = public_key_from(owf["jwk"]["x"], owf["jwk"]["y"])
    issuer = owf["issuer"]
    for entry in owf["lists"]:
        grant = authority(issuer, entry["sub"], trusted, "the key mint.mjs signed with")
        check("%s (payload %d bytes)" % (entry["name"], entry["payload_bytes"]), entry["token"],
              entry["sub"], issuer, grant, [tuple(pair) for pair in entry["checks"]])
    first = owf["lists"][0]
    grant = authority(issuer, first["sub"], trusted, "the key mint.mjs signed with")
    control("signed by a key the verifier does not trust",
            S.decide(owf["controls"]["other_key"], index=0, expected_uri=first["sub"],
                     authority=grant, now=NOW, credential_issuer=issuer), "signature")
    control("expired an hour ago",
            S.decide(owf["controls"]["expired"], index=0, expected_uri=first["sub"],
                     authority=grant, now=NOW, credential_issuer=issuer), "expired")
    control("published for another uri",
            S.decide(first["token"], index=0, expected_uri=issuer + "/statuslists/other",
                     authority=grant, now=NOW, credential_issuer=issuer), "sub_mismatch")
    control("index past the end",
            S.decide(first["token"], index=first["entries"], expected_uri=first["sub"],
                     authority=grant, now=NOW, credential_issuer=issuer), "index")

    print("RESULT: %s" % ("every status matched and every control was refused" if not failures
                          else "%d failure(s): %s" % (len(failures), "; ".join(failures))))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
