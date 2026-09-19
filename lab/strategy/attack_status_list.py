#!/usr/bin/env python3
"""Adversaries against the Token Status List decision function. Each one MUST fail.

LAB. Record: lab/strategy/001-token-status-list.md.

Same rule as attacks/: an attack SUCCEEDS when the defense fails to stop it, and a suite that
cannot run is a hard error rather than a silent skip. The bar that matters here is narrower
than "it returns an error": every refusal must land as checked=False, because the single
failure mode worth building this to avoid is a verifier that reads "I could not evaluate the
status" as "the credential is not revoked".

So the assertion for every adversary below is the same one, twice: the call did not raise, and
the verdict does not say VALID.

    python3 lab/strategy/attack_status_list.py
"""
from __future__ import annotations

import base64
import json
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from status_list import (INVALID, MAX_DECOMPRESSED_BYTES, SUSPENDED, VALID,  # noqa: E402
                         decide, encode_status_list, status_at)

NOW = 1_800_000_000
URI = "https://issuer.example/statuslists/1"


def b64u(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def token(payload, typ="statuslist+jwt", signature=b"sig"):
    header = {"alg": "ES256", "typ": typ, "kid": "k1"}
    return ".".join([b64u(json.dumps(header)), b64u(json.dumps(payload)), b64u(signature)])


def good_payload(statuses=(VALID, INVALID, SUSPENDED, VALID), bits=1, **over):
    if bits == 1:
        statuses = tuple(1 if s else 0 for s in statuses)
    p = {"sub": URI, "iat": NOW - 60, "exp": NOW + 3600, "ttl": 600,
         "status_list": {"bits": bits, "lst": encode_status_list(statuses, bits)}}
    p.update(over)
    return p


def accept_all(signing_input, signature, header):
    return True


def refuse_all(signing_input, signature, header):
    return False


# --------------------------------------------------------------------------- positive control

def positive_control():
    """Without this, every refusal below passes for the wrong reason.

    A decision function that returns checked=False to everything satisfies every adversary in
    this file while establishing nothing. The suite is VOID if this does not hold.
    """
    v = decide(token(good_payload(bits=2)), index=1, expected_uri=URI,
               verify_signature=accept_all, now=NOW)
    if not v["checked"] or v["status"] != INVALID:
        return False, "the control did not read a published INVALID: %r" % (dict(v),)
    v2 = decide(token(good_payload(bits=2)), index=0, expected_uri=URI,
                verify_signature=accept_all, now=NOW)
    if not v2["checked"] or v2["status"] != VALID:
        return False, "the control did not read a published VALID: %r" % (dict(v2),)
    v3 = decide(token(good_payload(bits=2)), index=2, expected_uri=URI,
                verify_signature=accept_all, now=NOW)
    if not v3["checked"] or v3["status"] != SUSPENDED:
        return False, "the control did not read a published SUSPENDED: %r" % (dict(v3),)
    return True, ("a published VALID, INVALID and SUSPENDED each read back correctly, so a "
                  "refusal below is evidence")


# --------------------------------------------------------------------------- the adversaries

def a_bit_order_reversed():
    """The silent one. If bits are read from the wrong end, every status still decodes.

    0xB9 holds indices 0..7 as 1,0,0,1,1,1,0,1 reading from the least significant bit. An
    implementation that reads the other way returns a real-looking answer belonging to a
    different credential, and no test that only checks index 0 of an all-zero list notices.
    """
    array = bytes([0xB9])
    want = [1, 0, 0, 1, 1, 1, 0, 1]
    got = [status_at(array, i, 1) for i in range(8)]
    if got != want:
        return True, "bit order is wrong: 0xB9 read as %r, the draft says %r" % (got, want)
    return False, "0xB9 reads as %r, least significant bit first, as the draft specifies" % (got,)


def a_index_past_the_end():
    """A list that does not cover this credential must not answer for it.

    The tempting implementation returns 0 for a short array, and 0 is VALID.
    """
    v = decide(token(good_payload()), index=10_000, expected_uri=URI,
               verify_signature=accept_all, now=NOW)
    if v["checked"]:
        return True, "an index past the end of the list returned a status: %r" % (dict(v),)
    return False, "an index past the end is refused (%s), not read as VALID" % v["code"]


def a_status_list_for_another_issuer():
    """A genuine, unexpired, correctly signed status list. For somebody else.

    This is the attack the `sub` binding exists for, and it is the one a naive implementation
    is most likely to allow, because every single other check passes.
    """
    other = good_payload(sub="https://issuer.example/statuslists/99")
    v = decide(token(other), index=1, expected_uri=URI,
               verify_signature=accept_all, now=NOW)
    if v["checked"]:
        return True, "a status list published for another URI answered for this credential"
    return False, "a real status list for another URI is refused (%s)" % v["code"]


def a_plain_jwt_replayed_as_a_status_list():
    """Any other signed object the issuer ever minted, offered here."""
    v = decide(token(good_payload(), typ="JWT"), index=1, expected_uri=URI,
               verify_signature=accept_all, now=NOW)
    if v["checked"]:
        return True, "a token declaring typ=JWT was accepted as a status list"
    return False, "a token that is not typ=statuslist+jwt is refused (%s)" % v["code"]


def a_expired_list_still_answers():
    v = decide(token(good_payload(exp=NOW - 1)), index=1, expected_uri=URI,
               verify_signature=accept_all, now=NOW)
    if v["checked"]:
        return True, "an expired status list still answered"
    return False, "an expired status list is refused (%s); the draft says MUST NOT" % v["code"]


def a_rollback_to_before_the_revocation():
    """THE interesting one, and the reason this is worth building carefully.

    An attacker who can serve a stale but still-unexpired status list un-revokes a credential.
    Nothing about that token is malformed: it was genuine when it was minted. The only defense
    is age, so the verdict must carry it and a caller must be able to bound it.

    The attack SUCCEEDS if a caller who asked for a 300-second bound is told the answer is
    fresh.
    """
    old = good_payload(statuses=(VALID, VALID, VALID, VALID), iat=NOW - 86_400,
                       exp=NOW + 3600, ttl=None)
    v = decide(token(old), index=1, expected_uri=URI, verify_signature=accept_all,
               now=NOW, max_age_seconds=300)
    if not v["checked"]:
        return False, ("a day-old status list is refused outright (%s), so the rollback has "
                       "nothing to work with" % v["code"])
    if v["fresh"] or not v["stale"]:
        return True, ("a status list minted %ds ago was reported fresh against a 300s bound; "
                      "a revocation can be rolled back invisibly" % v["age_seconds"])
    return False, ("a day-old list still answers, but is reported stale with age=%ds, so the "
                   "caller can refuse it" % v["age_seconds"])


def a_decompression_bomb():
    """`lst` arrives over the network from a URI named inside the credential.

    A verifier that dies on one credential fails open for every other credential in the queue,
    so this must be a refusal and not a MemoryError.
    """
    bomb = base64.urlsafe_b64encode(
        zlib.compress(b"\x00" * (MAX_DECOMPRESSED_BYTES * 4), 9)).rstrip(b"=").decode()
    p = good_payload()
    p["status_list"]["lst"] = bomb
    v = decide(token(p), index=1, expected_uri=URI, verify_signature=accept_all, now=NOW)
    if v["checked"]:
        return True, "a decompression bomb was expanded and answered from"
    return False, "a decompression bomb is refused (%s) without being expanded" % v["code"]


def a_unsigned_list():
    v = decide(token(good_payload()), index=1, expected_uri=URI,
               verify_signature=refuse_all, now=NOW)
    if v["checked"]:
        return True, "a status list whose signature did not verify still answered"
    return False, "a status list whose signature does not verify is refused (%s)" % v["code"]


def a_resolver_that_raises():
    def explode(signing_input, signature, header):
        raise RuntimeError("the key resolver is down")
    v = decide(token(good_payload()), index=1, expected_uri=URI,
               verify_signature=explode, now=NOW)
    if v["checked"]:
        return True, "a crashing key resolver was treated as a successful verification"
    return False, "a crashing key resolver is refused (%s), not read as a pass" % v["code"]


def a_unknown_status_folded_into_valid():
    """Value 3 is application-specific. It is not VALID, and must not be reported as one."""
    p = good_payload(statuses=(0, 3, 0, 0), bits=2)
    v = decide(token(p), index=1, expected_uri=URI, verify_signature=accept_all, now=NOW)
    if not v["checked"]:
        return False, "an application-specific status is refused (%s)" % v["code"]
    if v["status"] == VALID or v["meaning"] == "VALID":
        return True, "an application-specific status 3 was reported as VALID"
    return False, ("an application-specific status is reported by number (status=%r, "
                   "meaning=%r) rather than folded into VALID" % (v["status"], v["meaning"]))


def a_malformed_everything():
    """Total on hostile input: none of these may raise, and none may answer."""
    p = good_payload()
    bad_lst = dict(p, status_list={"bits": 1, "lst": "!!!not base64!!!"})
    cases = [
        ("empty", ""),
        ("two parts", "a.b"),
        ("header not json", "Zm9v.%s.c2ln" % b64u(json.dumps(good_payload()))),
        ("payload not json", "%s.Zm9v.c2ln" % b64u(json.dumps({"typ": "statuslist+jwt"}))),
        ("no status_list", token({"sub": URI, "iat": NOW - 1, "exp": NOW + 1})),
        ("bits=3", token(dict(p, status_list={"bits": 3, "lst": p["status_list"]["lst"]}))),
        ("bits=64", token(dict(p, status_list={"bits": 64, "lst": p["status_list"]["lst"]}))),
        ("lst not base64", token(bad_lst)),
        ("lst not zlib", token(dict(p, status_list={"bits": 1, "lst": b64u(b"not zlib")}))),
        ("iat is a string", token(dict(p, iat="soon"))),
        ("ttl is a bool", token(dict(p, ttl=True))),
        ("iat in the future", token(dict(p, iat=NOW + 5000, exp=NOW + 9000))),
        ("no sub", token({k: v for k, v in p.items() if k != "sub"})),
    ]
    for label, tok in cases:
        try:
            v = decide(tok, index=1, expected_uri=URI, verify_signature=accept_all, now=NOW)
        except Exception as exc:
            return True, "%r raised %s: %s" % (label, type(exc).__name__, exc)
        if v["checked"]:
            return True, "%r was accepted and answered: %r" % (label, dict(v))
    for label, idx in (("negative index", -1), ("boolean index", True),
                       ("string index", "1"), ("float index", 1.5)):
        try:
            v = decide(token(p), index=idx, expected_uri=URI, verify_signature=accept_all,
                       now=NOW)
        except Exception as exc:
            return True, "%r raised %s: %s" % (label, type(exc).__name__, exc)
        if v["checked"]:
            return True, "%r was accepted and answered" % label
    return False, "%d malformed tokens and 4 malformed indices: none raised, none answered" \
                  % len(cases)


ATTACKS = [
    ("bit_order_reversed", a_bit_order_reversed),
    ("index_past_the_end", a_index_past_the_end),
    ("status_list_for_another_issuer", a_status_list_for_another_issuer),
    ("plain_jwt_replayed", a_plain_jwt_replayed_as_a_status_list),
    ("expired_list_still_answers", a_expired_list_still_answers),
    ("rollback_to_before_revocation", a_rollback_to_before_the_revocation),
    ("decompression_bomb", a_decompression_bomb),
    ("unsigned_list", a_unsigned_list),
    ("resolver_that_raises", a_resolver_that_raises),
    ("unknown_status_folded_into_valid", a_unknown_status_folded_into_valid),
    ("malformed_everything", a_malformed_everything),
]


def main():
    ok, note = positive_control()
    print("== positive control ==")
    print("  [%s] %s" % ("ok" if ok else "VOID", note))
    if not ok:
        print("\nVOID: the control did not hold, so nothing below is evidence.")
        return 3
    print("\n== adversaries (each must FAIL) ==")
    broken, errors = [], []
    for name, fn in ATTACKS:
        try:
            succeeded, note = fn()
        except Exception as exc:
            print("  [ERROR ] %s raised %s: %s" % (name, type(exc).__name__, exc))
            errors.append(name)
            continue
        print("  [%-6s] %s: %s" % ("BROKEN" if succeeded else "held", name, note))
        if succeeded:
            broken.append(name)
    print()
    if errors:
        print("ERROR: %d attack(s) raised; cannot certify." % len(errors))
        return 3
    if broken:
        print("FAIL: %d attack(s) SUCCEEDED: %s" % (len(broken), ", ".join(broken)))
        return 1
    print("OK: all %d attacks failed to break the decision function." % len(ATTACKS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
