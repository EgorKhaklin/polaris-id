# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The Yivi walk's public files carry no holder data (lab/interop/yivi).

public_guard.problems() refuses, in a file or in any base64 or base64url token inside it, decoded
and scanned again: a disclosure, an SD-JWT, a key binding JWT, an issuer-signed credential, a
`cnf` member, an `_sd` digest list, an email address, an `email` member, and any value the caller
withholds; it opens gzip, line-wrapped base64 and percent-encoding on the way. Each refusal is
shown here on a made-up file, and each reviewer probe is one test. Then every directory under
lab/interop/yivi that holds a result.json (the live run, each rehearsal, each capture walk.sh
writes) is found and held to it; a directory that is missing or empty fails, so a check that
read nothing cannot pass. When the private capture of the live walk is on this machine, the
presenter's email domain is read from it at check time and is refused too; it is never written
into this tree, and this test never prints it.
"""
import base64
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import public_guard  # noqa: E402

PRIVATE_LIVE = pathlib.Path.home() / "Desktop/polaris-private/captures/yivi"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwt(header, payload):
    return "%s.%s.%s" % (b64u(json.dumps(header).encode()), b64u(json.dumps(payload).encode()),
                         b64u(b"s" * 64))


def disclosure(name, value):
    return b64u(json.dumps(["c2FsdHNhbHRzYWx0", name, value]).encode())


ISSUER_JWT = jwt({"alg": "ES256", "typ": "dc+sd-jwt"},
                 {"iss": "https://issuer.example", "_sd": ["x" * 43], "_sd_alg": "sha-256",
                  "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "a" * 43, "y": "b" * 43}}})
KB_JWT = jwt({"alg": "ES256", "typ": "kb+jwt"}, {"aud": "x509_hash:abc", "nonce": "n" * 22})
SD_JWT = ISSUER_JWT + "~" + disclosure("domain", "example.org") + "~" + KB_JWT


class Guard(unittest.TestCase):
    def problems(self, text, **kw):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "capture.json"
            path.write_text(text, encoding="utf-8")
            return public_guard.problems(path, **kw)

    def refused(self, text, **kw):
        found = self.problems(text, **kw)
        self.assertTrue(found, "the guard let this through: %r" % text[:120])
        return found

    # The shapes it was written for.
    def test_an_sd_jwt_is_refused(self):
        self.refused(json.dumps({"vp_token": SD_JWT}))

    def test_a_key_binding_jwt_is_refused(self):
        self.refused(json.dumps({"kb": KB_JWT}))

    def test_a_disclosure_is_refused(self):
        self.refused("disclosed: %s\n" % disclosure("domain", "example.org"))

    def test_a_cnf_member_is_refused(self):
        self.refused(json.dumps({"claims": {"cnf": {"jwk": {"kty": "EC"}}}}))

    def test_an_sd_digest_list_is_refused(self):
        self.refused(json.dumps({"_sd": ["x" * 43]}))

    # An email address, and an email member, whatever its value.
    def test_an_email_address_is_refused(self):
        self.refused(json.dumps({"note": "presented by someone@example.org"}))
        self.refused("contact someone@example.org\n")

    def test_an_email_member_is_refused_whatever_its_value(self):
        for value in ("someone", "", None, 1, ["a"], {"a": 1}):
            self.refused(json.dumps({"claims": {"email": value}}))

    # Tokens are decoded and scanned again.
    def test_a_base64_wrapped_sd_jwt_is_refused(self):
        wrapped = base64.b64encode(SD_JWT.encode()).decode("ascii")
        self.refused(json.dumps({"blob": wrapped}))
        self.refused("blob %s\n" % b64u(SD_JWT.encode()))

    def test_a_long_base64_token_is_decoded_and_rescanned(self):
        inner = json.dumps({"claims": {"cnf": {"jwk": {"kty": "EC"}}}}).encode()
        self.refused(json.dumps({"blob": base64.b64encode(inner).decode("ascii")}))
        email = json.dumps({"to": "someone@example.org"}).encode()
        self.refused("blob %s\n" % b64u(email))

    def test_a_withheld_value_is_refused_plain_and_wrapped(self):
        self.refused(json.dumps({"domain": "withheld-domain.example"}),
                     withheld=["withheld-domain.example"])
        wrapped = base64.b64encode(b'{"d": "withheld-domain.example"}').decode("ascii")
        self.refused(json.dumps({"blob": wrapped}), withheld=["withheld-domain.example"])

    # The reviewer's probes. Each asserts the reason, so a guard that refuses a file without
    # seeing what is inside it does not pass.
    def raw_problems(self, raw, name="capture.bin"):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / name
            path.write_bytes(raw)
            return public_guard.problems(path)

    def assert_reason(self, found, reason):
        self.assertTrue(any(reason in p for p in found), "%r not among %r" % (reason, found))

    def test_probe_a_plain_email(self):
        self.assert_reason(self.problems("someone@example.org\n"), "an email address")

    def test_probe_an_email_inside_a_log_line(self):
        self.assert_reason(self.problems(
            "2026-10-14T03:38:57Z INF presented by someone@example.org for x509_hash:abc\n"),
            "an email address")

    def test_probe_double_base64(self):
        once = base64.b64encode(json.dumps({"cnf": {"jwk": {"kty": "EC"}}}).encode())
        twice = base64.b64encode(once).decode("ascii")
        self.assert_reason(self.problems("blob %s\n" % twice), "a cnf member")
        email_twice = base64.b64encode(base64.b64encode(b"someone@example.org")).decode("ascii")
        self.assert_reason(self.problems("blob %s\n" % email_twice), "an email address")

    def test_probe_a_bare_sd_jwt(self):
        found = self.problems(SD_JWT + "\n", ) + self.raw_problems(SD_JWT.encode(), "token.txt")
        for reason in ("an SD-JWT", "a JWT of typ kb+jwt", "a disclosure", "a cnf member",
                       "an _sd digest list"):
            self.assert_reason(found, reason)

    def test_probe_gzip_raw(self):
        import gzip
        packed = gzip.compress(json.dumps({"vp_token": SD_JWT, "to": "someone@example.org"}).encode())
        found = self.raw_problems(packed, "capture.json.gz")
        for reason in ("gzip", "an SD-JWT", "an email address"):
            self.assert_reason(found, reason)

    def test_probe_gzip_base64_wrapped(self):
        import gzip
        packed = gzip.compress(json.dumps({"to": "someone@example.org", "vp": SD_JWT}).encode())
        found = self.problems(json.dumps({"blob": base64.b64encode(packed).decode("ascii")}))
        for reason in ("gzip", "an SD-JWT", "an email address"):
            self.assert_reason(found, reason)

    def test_probe_deeper_than_the_bound_is_refused(self):
        blob = json.dumps({"cnf": {"jwk": {"kty": "EC"}}}).encode()
        for _ in range(public_guard.MAX_DEPTH + 2):
            blob = base64.b64encode(blob)
        self.assert_reason(self.problems("blob %s\n" % blob.decode("ascii")), "the decode bound")

    def test_probe_gzip_that_does_not_decompress_is_refused(self):
        self.assert_reason(self.raw_problems(b"\x1f\x8b\x08\x00garbage", "x.gz"), "gzip")

    # Round three: a guard that measures nothing fails closed, and two more wrappings are opened.
    def test_check_dir_of_a_missing_directory_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assert_reason(public_guard.check_dir(pathlib.Path(d) / "absent"),
                               "does not exist")

    def test_check_dir_of_an_empty_directory_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assert_reason(public_guard.check_dir(d), "holds no file")

    def test_line_wrapped_base64_is_joined_and_read(self):
        wrapped = base64.encodebytes(SD_JWT.encode()).decode("ascii")
        self.assertGreater(wrapped.count("\n"), 2)
        self.assert_reason(self.problems(wrapped), "an SD-JWT")
        self.assert_reason(self.problems(wrapped), "a cnf member")

    def test_a_percent_encoded_email_is_refused(self):
        self.assert_reason(self.problems("redirect?to=someone%40example.org\n"),
                           "an email address")

    def test_a_percent_encoded_email_member_is_refused(self):
        self.assert_reason(self.problems("form wallet_metadata=%7B%22email%22%3A%20%22x%22%7D\n"),
                           "an email member")

    def test_a_percent_encoded_sd_jwt_is_refused(self):
        encoded = SD_JWT.replace(".", "%2E").replace("~", "%7E")
        found = self.problems(encoded + "\n")
        self.assert_reason(found, "an SD-JWT")
        self.assert_reason(found, "a JWT of typ kb+jwt")

    # Cheap closures of the reviewer's other probes.
    def test_a_jwe_is_refused(self):
        self.assert_reason(self.problems(b64u(b'{"alg":"ECDH-ES","enc":"A128GCM"}')
                                         + "..aaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccccccc\n"), "a JWE")

    def test_an_ip_literal_email_is_refused(self):
        self.assert_reason(self.problems("someone@[192.168.0.1]\n"), "an email address")

    def test_a_disclosure_token_with_a_short_salt_is_refused(self):
        token = b64u(json.dumps(["c2FsdA", "domain", "example.org"]).encode())
        self.assert_reason(self.problems(json.dumps({"d": token})), "a disclosure")

    def test_a_key_binding_jwt_without_typ_is_refused(self):
        kb = jwt({"alg": "ES256"}, {"aud": "x509_hash:abc", "nonce": "n" * 22, "sd_hash": "h" * 43})
        self.assert_reason(self.problems(json.dumps({"kb": kb})), "an sd_hash member")

    def test_a_withheld_value_split_across_json_strings_is_refused(self):
        self.assert_reason(self.problems(json.dumps({"a": "withheld-dom", "b": "ain.example"}),
                                         withheld=["withheld-domain.example"]), "a withheld value")

    def test_a_misaligned_base64_withheld_value_is_refused(self):
        token = "x" + base64.b64encode(b"..withheld-domain.example..").decode("ascii")
        self.assert_reason(self.problems(token + "\n", withheld=["withheld-domain.example"]),
                           "a withheld value")

    # Positive controls: without these, every refusal above could be a guard that refuses all.
    def test_the_verifier_request_object_passes(self):
        request = jwt({"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": ["MIIB" + "A" * 300]},
                      {"client_id": "x509_hash:abc", "response_mode": "direct_post.jwt",
                       "client_metadata": {"jwks": {"keys": [{"kty": "EC", "x": "a" * 43}]}},
                       "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
                                                       "meta": {"vct_values": ["pbdf.sidn-pbdf.email"]},
                                                       "claims": [{"path": ["domain"]}]}]}})
        self.assertEqual(self.problems(request + "\n"), [])

    def test_a_withheld_placeholder_passes(self):
        self.assertEqual(self.problems(json.dumps(
            {"domain": "<the presenter's email domain, withheld>",
             "vct": "pbdf.sidn-pbdf.email", "iss": "https://is.yivi.app"})), [])


def withheld_from_private_capture():
    """The disclosed values of the live walk, read from the private capture on this machine."""
    values = set()
    for response in sorted(PRIVATE_LIVE.glob("live-*/response-*.json")):
        token = json.loads(response.read_text()).get("vp_token") or {}
        for presentations in token.values():
            for presentation in presentations if isinstance(presentations, list) else [presentations]:
                for part in str(presentation).split("~")[1:]:
                    try:
                        decoded = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
                    except ValueError:
                        continue
                    if isinstance(decoded, list) and len(decoded) == 3 and isinstance(decoded[2], str):
                        values.add(decoded[2])
    return sorted(values)


def public_dirs():
    """Every directory under lab/interop/yivi holding a result.json: the live run, each rehearsal,
    and each capture walk.sh writes, found rather than named, so a new one is held to the guard."""
    return sorted({p.parent for p in HERE.rglob("result.json")})


class PublicFiles(unittest.TestCase):
    def test_the_public_directories_exist(self):
        dirs = public_dirs()
        self.assertIn(HERE / "live-2026-10-14", dirs)
        self.assertTrue((HERE / "live-2026-10-14" / "request-object.jwt").is_file())
        self.assertTrue(any("rehearsal" in d.parts for d in dirs), dirs)

    def test_no_public_file_carries_holder_data(self):
        dirs = public_dirs()
        self.assertTrue(dirs, "no public directory was found, so nothing was checked")
        for directory in dirs:
            self.assertEqual(public_guard.check_dir(directory), [], directory)

    def test_no_public_file_carries_the_withheld_domain(self):
        values = withheld_from_private_capture()
        if not values:
            self.skipTest("the live walk's private capture is not on this machine")
        for directory in public_dirs() + [HERE]:
            leaks = [p for p in public_guard.check_dir(directory, withheld=values)
                     if "a withheld value" in p]
            # Report the files, never the value.
            self.assertEqual([p.split(":")[0] for p in leaks], [], directory)

    def test_the_live_result_states_one_disclosure_and_withholds_it(self):
        result = json.loads((HERE / "live-2026-10-14" / "result.json").read_text())
        verdict = result["live_verdict"]
        self.assertEqual(verdict["selectively_disclosed"], ["domain"])
        self.assertEqual(verdict["domain"], "<the presenter's email domain, withheld>")
        self.assertNotIn("cnf", json.dumps(verdict.get("values", {})))


if __name__ == "__main__":
    unittest.main()
