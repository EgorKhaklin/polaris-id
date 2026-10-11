# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Tests for polaris-release-tag-guard.py: a publish never moves a published release tag.

The registry is a stub that answers the two requests the guard makes (the token, then the
manifest under the tag), so each of the four outcomes runs without a network: an absent tag
proceeds, the same two digests proceed, any other index refuses, and any other answer refuses.
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("tag_guard", _HERE / "polaris-release-tag-guard.py")
tag_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tag_guard)

AMD64 = "sha256:" + "a" * 64
ARM64 = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64
REPO = "egorkhaklin/polaris-app"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
TOKEN_OK = (200, json.dumps({"token": "t0k"}).encode())


def _index(entries, media_type=OCI_INDEX):
    return (200, json.dumps({
        "schemaVersion": 2, "mediaType": media_type,
        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": d,
                       "size": 1000, "platform": p} for d, p in entries]}).encode())


SAME = _index([(AMD64, {"os": "linux", "architecture": "amd64"}),
               (ARM64, {"os": "linux", "architecture": "arm64", "variant": "v8"})])


def _error(status, code=None):
    return (status, json.dumps({"errors": [{"code": code, "message": "x"}]} if code else {}).encode())


class Registry:
    """Answers the token request, then the manifest request, and records both."""

    def __init__(self, manifest, token=TOKEN_OK):
        self.token, self.manifest, self.calls = token, manifest, []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        return self.token if "/token?" in url else self.manifest


def _publish(registry, amd64=AMD64, arm64=ARM64, tag="v1.0.0", env=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = tag_guard.main(["--repo", REPO, "--tag", tag, "--amd64", amd64, "--arm64", arm64],
                              get=registry, env=env or {})
    return code, out.getvalue() + err.getvalue()


def _dry(registry, *extra):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = tag_guard.main(["--dry", "--repo", REPO, *extra], get=registry, env={})
    return code, out.getvalue()


class AbsentTagProceeds(unittest.TestCase):
    """The first publish of a tag: the registry knows neither the tag nor, before any push,
    the repository."""

    def test_manifest_unknown_proceeds(self):
        code, said = _publish(Registry(_error(404, "MANIFEST_UNKNOWN")))
        self.assertEqual(code, 0, said)
        self.assertIn("first publish", said)

    def test_name_unknown_proceeds(self):
        self.assertEqual(_publish(Registry(_error(404, "NAME_UNKNOWN")))[0], 0)

    def test_a_404_without_a_registry_code_refuses(self):
        # A proxy's or an outage's 404 is not the registry saying the tag is absent.
        code, said = _publish(Registry(_error(404)))
        self.assertEqual(code, 1, said)


class SameDigestsProceed(unittest.TestCase):
    """"Re-run failed jobs" in the run that published the tag reuses its build digests."""

    def test_the_same_two_digests_proceed(self):
        code, said = _publish(Registry(SAME))
        self.assertEqual(code, 0, said)
        self.assertIn("re-run", said)

    def test_the_docker_manifest_list_form_reads_the_same(self):
        same = _index([(AMD64, {"os": "linux", "architecture": "amd64"}),
                       (ARM64, {"os": "linux", "architecture": "arm64"})],
                      "application/vnd.docker.distribution.manifest.list.v2+json")
        self.assertEqual(_publish(Registry(same))[0], 0)


class OtherIndexRefuses(unittest.TestCase):
    """A fresh dispatch on a published tag rebuilds, and its digests differ."""

    def test_a_different_digest_refuses(self):
        code, said = _publish(Registry(SAME), amd64=OTHER)
        self.assertEqual(code, 1, said)
        self.assertIn("never moves", said)

    def test_the_architectures_swapped_refuse(self):
        self.assertEqual(_publish(Registry(SAME), amd64=ARM64, arm64=AMD64)[0], 1)

    def test_an_extra_entry_refuses(self):
        extra = _index([(AMD64, {"os": "linux", "architecture": "amd64"}),
                        (ARM64, {"os": "linux", "architecture": "arm64"}),
                        (OTHER, {"os": "unknown", "architecture": "unknown"})])
        self.assertEqual(_publish(Registry(extra))[0], 1)

    def test_a_duplicated_platform_refuses(self):
        dup = _index([(AMD64, {"os": "linux", "architecture": "amd64"}),
                      (ARM64, {"os": "linux", "architecture": "arm64"}),
                      (OTHER, {"os": "linux", "architecture": "arm64"})])
        self.assertEqual(_publish(Registry(dup))[0], 1)

    def test_an_empty_index_refuses(self):
        self.assertEqual(_publish(Registry(_index([])))[0], 1)


class AnyOtherAnswerRefuses(unittest.TestCase):

    def test_a_refused_token_refuses(self):
        code, said = _publish(Registry(_error(404, "MANIFEST_UNKNOWN"), token=_error(403, "DENIED")))
        self.assertEqual(code, 1, said)
        self.assertIn("could not be read", said)

    def test_a_token_body_without_a_token_refuses(self):
        self.assertEqual(_publish(Registry(SAME, token=(200, b'{"nope": 1}')))[0], 1)

    def test_each_error_status_refuses(self):
        for status, code in ((401, "UNAUTHORIZED"), (403, "DENIED"), (429, "TOOMANYREQUESTS"),
                             (500, None), (503, None), (0, None)):
            with self.subTest(status=status):
                self.assertEqual(_publish(Registry(_error(status, code)))[0], 1)

    def test_a_body_that_is_not_json_refuses(self):
        self.assertEqual(_publish(Registry((200, b"<html>")))[0], 1)

    def test_a_single_image_manifest_under_the_tag_refuses(self):
        single = (200, json.dumps({"schemaVersion": 2, "mediaType":
                                   "application/vnd.oci.image.manifest.v1+json"}).encode())
        code, said = _publish(Registry(single))
        self.assertEqual(code, 1, said)
        self.assertIn("other than an image index", said)

    def test_a_body_that_lists_the_same_digests_but_is_not_an_index_refuses(self):
        # Only an index joins the two architectures; the same list under another type is not one.
        lookalike = _index([(AMD64, {"os": "linux", "architecture": "amd64"}),
                            (ARM64, {"os": "linux", "architecture": "arm64"})],
                           "application/vnd.oci.image.manifest.v1+json")
        self.assertEqual(_publish(Registry(lookalike))[0], 1)


class Usage(unittest.TestCase):

    def test_a_publish_must_name_both_digests(self):
        for amd64, arm64 in (("", ARM64), (AMD64, ""), ("sha256:short", ARM64), (AMD64, "latest")):
            with self.subTest(amd64=amd64, arm64=arm64):
                registry = Registry(_error(404, "MANIFEST_UNKNOWN"))
                self.assertEqual(_publish(registry, amd64=amd64, arm64=arm64)[0], 2)
                self.assertEqual(registry.calls, [], "a usage error reads nothing")

    def test_a_publish_must_name_a_release_tag(self):
        for tag in ("", "main", "1.0.0", "v1.0", "v1.0.0 "):
            with self.subTest(tag=tag):
                self.assertEqual(_publish(Registry(SAME), tag=tag)[0], 2)

    def test_a_publish_cannot_take_its_tag_from_the_version_file(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = tag_guard.main(["--repo", REPO, "--version-file", "x", "--amd64", AMD64,
                                   "--arm64", ARM64], get=Registry(SAME), env={})
        self.assertEqual(code, 2)


class Requests(unittest.TestCase):

    def test_the_token_is_asked_with_the_workflow_credentials_and_the_tag_with_the_bearer(self):
        registry = Registry(_error(404, "MANIFEST_UNKNOWN"))
        _publish(registry, env={"GHCR_USER": "bot", "GHCR_TOKEN": "s3cret"})
        (token_url, token_headers), (manifest_url, manifest_headers) = registry.calls
        self.assertEqual(token_url, "https://ghcr.io/token?service=ghcr.io"
                                    "&scope=repository:egorkhaklin/polaris-app:pull")
        self.assertEqual(token_headers["Authorization"], "Basic Ym90OnMzY3JldA==")
        self.assertEqual(manifest_url, "https://ghcr.io/v2/egorkhaklin/polaris-app/manifests/v1.0.0")
        self.assertEqual(manifest_headers["Authorization"], "Bearer t0k")
        self.assertIn(OCI_INDEX, manifest_headers["Accept"])

    def test_without_credentials_the_read_is_anonymous(self):
        registry = Registry(_error(404, "MANIFEST_UNKNOWN"))
        _publish(registry)
        self.assertNotIn("Authorization", registry.calls[0][1])


class DryRun(unittest.TestCase):
    """The dry run reads the tag the publish will meet, reports it, and never blocks."""

    def test_an_absent_tag_says_so(self):
        code, said = _dry(Registry(_error(404, "MANIFEST_UNKNOWN")), "--tag", "v1.0.0")
        self.assertEqual(code, 0)
        self.assertIn("ghcr.io/egorkhaklin/polaris-app:v1.0.0: would publish to an absent tag", said)

    def test_a_published_tag_and_an_unreadable_one_are_reported_not_refused(self):
        self.assertIn("published as", _dry(Registry(SAME), "--tag", "v1.0.0")[1])
        code, said = _dry(Registry(_error(403, "DENIED")), "--tag", "v1.0.0")
        self.assertEqual(code, 0)
        self.assertIn("a publish refuses on this answer", said)

    def test_on_a_branch_the_tag_comes_from_the_version_file(self):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "__version__.py").write_text('__version__: str = "1.0.0"\n')
        registry = Registry(_error(404, "MANIFEST_UNKNOWN"))
        code, said = _dry(registry, "--version-file", str(d / "__version__.py"))
        self.assertEqual(code, 0)
        self.assertTrue(registry.calls[1][0].endswith("/manifests/v1.0.0"), registry.calls)
        self.assertIn(":v1.0.0: would publish to an absent tag", said)


if __name__ == "__main__":
    unittest.main()
